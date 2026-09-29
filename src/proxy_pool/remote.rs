use super::{
    core::{
        port_for, wait_for_shutdown, ChildSpec, ChildTransport, ProxyAuth, SlotKey, Supervisor,
    },
    reporter::{Heartbeat, ProxyReport, RemoteReporter},
    state::{load_suffixes, save_suffixes, PoolState, ProxyRecord},
};
use anyhow::{Context, Result};
use futures::future::join_all;
use ring::rand::SecureRandom;
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::Command,
};

const PROBE_HOST: &str = "api.ipify.org";
const PROBE_PORT: u16 = 80;

#[derive(Clone, Debug)]
pub struct RemoteConfig {
    pub root: PathBuf,
    pub prefixes: Vec<String>,
    pub interface: Option<String>,
    pub slots_per_prefix: usize,
    pub topup_count: usize,
    pub stale_limit: usize,
    pub base_port: u16,
    pub port_stride: u16,
    pub auth: ProxyAuth,
    pub transport: ChildTransport,
    pub registration_delay: Duration,
    pub probe_wait: Duration,
    pub heartbeat_interval: Duration,
    pub register_interval: Duration,
    pub drift_interval: Duration,
    pub orchestrator_url: String,
    pub psk: String,
    pub hostname: String,
}

pub async fn run(config: RemoteConfig) -> Result<()> {
    validate_config(&config)?;
    fs::create_dir_all(&config.root)?;

    let reporter = RemoteReporter::new(config.orchestrator_url.clone(), config.psk.clone())?;
    let state_path = config.root.join("state.json");
    let mut state = PoolState::load(&state_path)?;
    let (box_v6, box_v4) = discover_box_addresses(&config.prefixes).await;
    state.box_v6 = box_v6;
    state.box_v4 = box_v4;

    prepare_proxy_records(&config, &mut state).await?;
    if state.phase != "locked" {
        state.phase = "init".to_string();
    }
    if state.proxies.iter().all(|proxy| proxy.locked) && !state.proxies.is_empty() {
        state.phase = "locked".to_string();
    } else if !state.proxies.iter().any(|proxy| proxy.locked) {
        state.phase = "init".to_string();
    }
    state.save(&state_path)?;

    let mut supervisor = Supervisor::new(config.root.clone())?;
    for index in 0..state.proxies.len() {
        let group = state.proxies[index].group;
        let slot = state.proxies[index].slot;
        let created = supervisor.ensure_identity(group, slot).await?;
        state.proxies[index].registered = true;
        if created && !config.registration_delay.is_zero() {
            tokio::time::sleep(config.registration_delay).await;
        }
    }
    state.save(&state_path)?;

    for index in 0..state.proxies.len() {
        if !state.proxies[index].locked {
            continue;
        }
        let spec = child_spec(&config, &state.proxies[index])?;
        let pid = supervisor.start(&spec).await?;
        state.proxies[index].pid = pid;
    }

    let mut last_heartbeat = Instant::now()
        .checked_sub(config.heartbeat_interval)
        .unwrap_or_else(Instant::now);
    let mut last_register = Instant::now()
        .checked_sub(config.register_interval)
        .unwrap_or_else(Instant::now);
    let mut last_drift = Instant::now();
    let mut cycle_cursor = 0usize;
    let mut cpu = CpuSampler::default();
    let mut cpu_history = Vec::with_capacity(10);
    let mut shutdown = Box::pin(wait_for_shutdown());

    loop {
        tokio::select! {
            result = &mut shutdown => {
                result?;
                break;
            }
            () = tokio::time::sleep(Duration::from_secs(1)) => {}
        }

        let mut changed = restart_dead_locked(&config, &mut state, &mut supervisor).await?;

        if state.phase == "init" {
            let cycling = state.proxies.iter().filter(|proxy| !proxy.locked).count();
            if cycling < config.topup_count {
                changed |= top_up_candidates(&config, &mut state).await?;
            }

            let locked = cycle_one(&config, &mut state, &mut supervisor, &mut cycle_cursor).await?;
            changed |= locked;
            if locked {
                if let Err(error) = send_register(&config, &state, &reporter).await {
                    log::warn!("orchestrator register after new lock failed: {error:#}");
                }
                last_register = Instant::now();
            }

            let locked_count = state.proxies.iter().filter(|proxy| proxy.locked).count();
            let cycling = state.proxies.len().saturating_sub(locked_count);
            if locked_count > 0 && (cycling == 0 || state.stale_count >= config.stale_limit) {
                state.phase = "locked".to_string();
                changed = true;
                log::info!(
                    "remote pool entering locked phase: {locked_count} locked, {cycling} spare candidates"
                );
                if let Err(error) = send_register(&config, &state, &reporter).await {
                    log::warn!("orchestrator register on lock transition failed: {error:#}");
                }
                last_register = Instant::now();
            }
        }

        if last_drift.elapsed() >= config.drift_interval {
            let drifted = check_drift(&config, &mut state, &mut supervisor).await?;
            if drifted {
                state.phase = "init".to_string();
                state.stale_count = 0;
                changed = true;
            }
            last_drift = Instant::now();
        }

        if last_register.elapsed() >= config.register_interval {
            if let Err(error) = send_register(&config, &state, &reporter).await {
                log::warn!("orchestrator register failed: {error:#}");
            }
            last_register = Instant::now();
        }

        if last_heartbeat.elapsed() >= config.heartbeat_interval {
            let stats = cpu.sample();
            cpu_history.push(stats.cpu_pct);
            if cpu_history.len() > 10 {
                cpu_history.remove(0);
            }
            if let Err(error) =
                send_heartbeat(&config, &state, &reporter, stats, &cpu_history).await
            {
                log::warn!("orchestrator heartbeat failed: {error:#}");
            }
            last_heartbeat = Instant::now();
        }

        if changed {
            state.save(&state_path)?;
        }
    }

    state.save(&state_path)?;
    supervisor.stop_all().await;
    Ok(())
}

fn validate_config(config: &RemoteConfig) -> Result<()> {
    if config.prefixes.is_empty() {
        anyhow::bail!("remote pool requires at least one routed IPv6 /64 prefix");
    }
    if config.slots_per_prefix == 0 {
        anyhow::bail!("slots per prefix must be greater than zero");
    }
    if config.topup_count == 0 {
        anyhow::bail!("top-up count must be greater than zero");
    }
    if config.stale_limit == 0 {
        anyhow::bail!("stale limit must be greater than zero");
    }
    if config.auth.username.is_empty() || config.auth.password.is_empty() {
        anyhow::bail!("remote proxy authentication must not be empty");
    }
    for prefix in &config.prefixes {
        let _ = parse_prefix64(prefix)?;
    }
    Ok(())
}

async fn prepare_proxy_records(config: &RemoteConfig, state: &mut PoolState) -> Result<()> {
    let mut old = HashMap::new();
    for proxy in state.proxies.drain(..) {
        match proxy.addr.parse::<Ipv6Addr>() {
            Ok(address) => {
                old.insert((proxy.group, address), proxy);
            }
            Err(error) => {
                log::warn!(
                    "discarding invalid persisted proxy address {:?}: {error}",
                    proxy.addr
                );
            }
        }
    }
    let mut records = Vec::new();

    for (group, prefix_text) in config.prefixes.iter().enumerate() {
        let prefix = parse_prefix64(prefix_text)?;
        let interface = match &config.interface {
            Some(interface) => interface.clone(),
            None => discover_interface(prefix_text).await?,
        };
        let mut suffixes = load_suffixes(&config.root, group)?;
        let mut known: HashSet<_> = suffixes.iter().cloned().collect();
        while suffixes.len() < config.slots_per_prefix {
            let suffix = random_suffix()?;
            if known.insert(suffix.clone()) {
                suffixes.push(suffix);
            }
        }
        save_suffixes(&config.root, group, &suffixes)?;

        for (slot, suffix) in suffixes.iter().enumerate() {
            let address = compose_address(prefix, suffix)?;
            ensure_host_address(&interface, address).await?;
            let address_text = address.to_string();
            let mut record = old
                .remove(&(group, address))
                .unwrap_or_else(|| ProxyRecord {
                    addr: address_text.clone(),
                    group,
                    slot,
                    ..ProxyRecord::default()
                });
            record.slot = slot;
            record.addr = address_text;
            records.push(record);
        }
    }

    state.proxies = records;
    state.v6_root = parse_prefix64(&config.prefixes[0])?.network_text();
    Ok(())
}

async fn top_up_candidates(config: &RemoteConfig, state: &mut PoolState) -> Result<bool> {
    let mut changed = false;
    for (group, prefix_text) in config.prefixes.iter().enumerate() {
        let prefix = parse_prefix64(prefix_text)?;
        let interface = match &config.interface {
            Some(interface) => interface.clone(),
            None => discover_interface(prefix_text).await?,
        };
        let mut suffixes = load_suffixes(&config.root, group)?;
        let start = suffixes.len();
        let target = start
            .checked_add(config.topup_count)
            .ok_or_else(|| anyhow::anyhow!("proxy candidate count overflow"))?;
        let mut known: HashSet<_> = suffixes.iter().cloned().collect();
        while suffixes.len() < target {
            let suffix = random_suffix()?;
            if known.insert(suffix.clone()) {
                suffixes.push(suffix);
            }
        }
        save_suffixes(&config.root, group, &suffixes)?;
        for (slot, suffix) in suffixes.iter().enumerate().skip(start) {
            let address = compose_address(prefix, suffix)?;
            ensure_host_address(&interface, address).await?;
            state.proxies.push(ProxyRecord {
                addr: address.to_string(),
                group,
                slot,
                ..ProxyRecord::default()
            });
            changed = true;
        }
    }
    Ok(changed)
}

async fn restart_dead_locked(
    config: &RemoteConfig,
    state: &mut PoolState,
    supervisor: &mut Supervisor,
) -> Result<bool> {
    let mut changed = false;
    for index in 0..state.proxies.len() {
        if !state.proxies[index].locked {
            continue;
        }
        let key = SlotKey {
            group: state.proxies[index].group,
            slot: state.proxies[index].slot,
        };
        if supervisor.is_running(key)? {
            continue;
        }
        let spec = child_spec(config, &state.proxies[index])?;
        let pid = supervisor.start(&spec).await?;
        state.proxies[index].pid = pid;
        changed = true;
        log::warn!(
            "restarted remote proxy g{} s{} pid={pid}",
            key.group,
            key.slot
        );
    }
    Ok(changed)
}

async fn cycle_one(
    config: &RemoteConfig,
    state: &mut PoolState,
    supervisor: &mut Supervisor,
    cursor: &mut usize,
) -> Result<bool> {
    if state.proxies.is_empty() {
        return Ok(false);
    }

    let len = state.proxies.len();
    let Some(index) = (0..len)
        .map(|offset| (*cursor + offset) % len)
        .find(|index| !state.proxies[*index].locked)
    else {
        return Ok(false);
    };
    *cursor = (index + 1) % len;

    let group = state.proxies[index].group;
    let slot = state.proxies[index].slot;
    let created = supervisor.ensure_identity(group, slot).await?;
    state.proxies[index].registered = true;
    if created && !config.registration_delay.is_zero() {
        tokio::time::sleep(config.registration_delay).await;
    }

    let spec = child_spec(config, &state.proxies[index])?;
    let pid = supervisor.start(&spec).await?;
    state.proxies[index].pid = pid;
    tokio::time::sleep(config.probe_wait).await;

    let key = SlotKey::from(&spec);
    if !supervisor.is_running(key)? {
        state.proxies[index].pid = 0;
        state.stale_count = state.stale_count.saturating_add(1);
        return Ok(false);
    }

    let listener = SocketAddr::new(spec.bind_ip, spec.port);
    let observed = match probe_v4(listener, &config.auth).await {
        Ok(value) => value,
        Err(error) => {
            log::warn!(
                "probe failed g{} s{} port={}: {error:#}",
                spec.group,
                spec.slot,
                spec.port
            );
            supervisor.stop(key).await?;
            state.proxies[index].pid = 0;
            state.stale_count = state.stale_count.saturating_add(1);
            return Ok(false);
        }
    };
    let observed_text = observed.to_string();

    if state.seen_v4.contains(&observed_text) {
        log::info!(
            "duplicate WARP v4 {observed} g{} s{}; cycling",
            spec.group,
            spec.slot
        );
        supervisor.stop(key).await?;
        state.proxies[index].pid = 0;
        state.stale_count = state.stale_count.saturating_add(1);
        return Ok(false);
    }

    state.seen_v4.insert(observed_text.clone());
    state.proxies[index].v4 = observed_text;
    state.proxies[index].v6 = state.proxies[index].addr.clone();
    state.proxies[index].locked = true;
    state.proxies[index].last_keepalive = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
    state.stale_count = 0;
    log::info!(
        "locked proxy g{} s{} port={} v4={observed}",
        spec.group,
        spec.slot,
        spec.port
    );
    Ok(true)
}

async fn check_drift(
    config: &RemoteConfig,
    state: &mut PoolState,
    supervisor: &mut Supervisor,
) -> Result<bool> {
    let mut work = Vec::new();
    for (index, proxy) in state.proxies.iter().enumerate() {
        if !proxy.locked {
            continue;
        }
        let key = SlotKey {
            group: proxy.group,
            slot: proxy.slot,
        };
        if !supervisor.is_running(key)? {
            continue;
        }
        let port = port_for(
            config.base_port,
            config.port_stride,
            proxy.group,
            proxy.slot,
        )?;
        let address: IpAddr = proxy.addr.parse()?;
        work.push((index, SocketAddr::new(address, port), proxy.v4.clone()));
    }

    let results = join_all(
        work.iter()
            .map(|(_, listener, _)| probe_v4(*listener, &config.auth)),
    )
    .await;

    let mut changed = false;
    for ((index, _listener, expected), result) in work.into_iter().zip(results) {
        let Ok(observed) = result else {
            continue;
        };
        let observed = observed.to_string();
        if !expected.is_empty() && observed != expected {
            let key = SlotKey {
                group: state.proxies[index].group,
                slot: state.proxies[index].slot,
            };
            log::warn!(
                "WARP egress drift g{} s{} {} -> {}",
                key.group,
                key.slot,
                expected,
                observed
            );
            supervisor.stop(key).await?;
            state.proxies[index].pid = 0;
            state.proxies[index].locked = false;
            state.proxies[index].v4 = observed;
            state.proxies[index].last_keepalive = 0.0;
            changed = true;
        }
    }
    Ok(changed)
}

fn child_spec(config: &RemoteConfig, proxy: &ProxyRecord) -> Result<ChildSpec> {
    let source: IpAddr = proxy
        .addr
        .parse()
        .with_context(|| format!("invalid proxy source address {:?}", proxy.addr))?;
    let mut transport = config.transport.clone();
    transport.use_ipv6_endpoint = true;
    Ok(ChildSpec {
        group: proxy.group,
        slot: proxy.slot,
        bind_ip: source,
        source_ip: Some(source),
        port: port_for(
            config.base_port,
            config.port_stride,
            proxy.group,
            proxy.slot,
        )?,
        auth: Some(config.auth.clone()),
        transport,
    })
}

async fn send_register(
    config: &RemoteConfig,
    state: &PoolState,
    reporter: &RemoteReporter,
) -> Result<()> {
    let reports = proxy_reports(config, state)?;
    reporter
        .register(
            &state.v6_root,
            &state.box_v6,
            &state.box_v4,
            &config.hostname,
            &reports,
        )
        .await
}

async fn send_heartbeat(
    config: &RemoteConfig,
    state: &PoolState,
    reporter: &RemoteReporter,
    stats: SystemStats,
    cpu_history: &[f64],
) -> Result<()> {
    let reports = proxy_reports(config, state)?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let uptime = ((now as f64) - state.started_at).max(0.0) as i64;
    reporter
        .heartbeat(&Heartbeat {
            v: 1,
            v6_root: &state.v6_root,
            box_v6: &state.box_v6,
            box_v4: &state.box_v4,
            hostname: &config.hostname,
            phase: &state.phase,
            locked_count: reports.len(),
            cycling_count: state.proxies.len().saturating_sub(reports.len()),
            seen_v4_count: state.seen_v4.len(),
            stale_count: state.stale_count,
            uptime,
            cpu_pct: stats.cpu_pct,
            mem_used_mb: stats.mem_used_mb,
            mem_total_mb: stats.mem_total_mb,
            cpu_history,
            proxies_delta: &reports,
        })
        .await
}

fn proxy_reports(config: &RemoteConfig, state: &PoolState) -> Result<Vec<ProxyReport>> {
    state
        .proxies
        .iter()
        .filter(|proxy| proxy.locked)
        .map(|proxy| {
            Ok(ProxyReport {
                v6: if proxy.v6.is_empty() {
                    proxy.addr.clone()
                } else {
                    proxy.v6.clone()
                },
                port: port_for(
                    config.base_port,
                    config.port_stride,
                    proxy.group,
                    proxy.slot,
                )?,
                v4: proxy.v4.clone(),
                group: proxy.group,
                slot: proxy.slot,
                auth: format!("{}:{}", config.auth.username, config.auth.password),
                locked_at: Some(proxy.last_keepalive as i64),
            })
        })
        .collect()
}

async fn probe_v4(listener: SocketAddr, auth: &ProxyAuth) -> Result<Ipv4Addr> {
    tokio::time::timeout(Duration::from_secs(10), probe_v4_inner(listener, auth))
        .await
        .context("proxy probe timed out")?
}

async fn probe_v4_inner(listener: SocketAddr, auth: &ProxyAuth) -> Result<Ipv4Addr> {
    let user = auth.username.as_bytes();
    let password = auth.password.as_bytes();
    let user_len = u8::try_from(user.len()).context("SOCKS username exceeds 255 bytes")?;
    let password_len = u8::try_from(password.len()).context("SOCKS password exceeds 255 bytes")?;

    let mut stream = TcpStream::connect(listener).await?;
    stream.write_all(&[5, 1, 2]).await?;
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 2] {
        anyhow::bail!("SOCKS server rejected username/password authentication");
    }

    let mut auth_request = Vec::with_capacity(user.len() + password.len() + 3);
    auth_request.extend_from_slice(&[1, user_len]);
    auth_request.extend_from_slice(user);
    auth_request.push(password_len);
    auth_request.extend_from_slice(password);
    stream.write_all(&auth_request).await?;
    let mut auth_reply = [0_u8; 2];
    stream.read_exact(&mut auth_reply).await?;
    if auth_reply != [1, 0] {
        anyhow::bail!("SOCKS authentication failed");
    }

    let host = PROBE_HOST.as_bytes();
    let host_len = u8::try_from(host.len()).context("probe hostname is too long")?;
    let mut request = Vec::with_capacity(host.len() + 7);
    request.extend_from_slice(&[5, 1, 0, 3, host_len]);
    request.extend_from_slice(host);
    request.extend_from_slice(&PROBE_PORT.to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0_u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 5 || reply[1] != 0 {
        anyhow::bail!("SOCKS CONNECT failed with reply {}", reply[1]);
    }
    consume_socks_address(&mut stream, reply[3]).await?;

    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let response = String::from_utf8(response).context("ipify returned non-UTF8 HTTP")?;
    let (_, body) = response
        .split_once("\r\n\r\n")
        .context("ipify returned malformed HTTP")?;
    body.trim()
        .parse()
        .with_context(|| format!("ipify returned non-IPv4 body {body:?}"))
}

async fn consume_socks_address(stream: &mut TcpStream, address_type: u8) -> Result<()> {
    let address_len = match address_type {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            usize::from(length[0])
        }
        other => anyhow::bail!("invalid SOCKS address type {other}"),
    };
    let mut address = vec![0_u8; address_len];
    stream.read_exact(&mut address).await?;
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(())
}

#[derive(Clone, Copy)]
struct Prefix64 {
    segments: [u16; 4],
}

impl Prefix64 {
    fn network_text(self) -> String {
        format!(
            "{:x}:{:x}:{:x}:{:x}",
            self.segments[0], self.segments[1], self.segments[2], self.segments[3]
        )
    }

    fn contains(self, address: Ipv6Addr) -> bool {
        let segments = address.segments();
        segments[..4] == self.segments
    }
}

fn parse_prefix64(value: &str) -> Result<Prefix64> {
    let (address, length) = value
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("IPv6 prefix must include /64: {value}"))?;
    if length != "64" {
        anyhow::bail!("remote pool currently requires /64 prefixes, got {value}");
    }
    let address: Ipv6Addr = address
        .parse()
        .with_context(|| format!("invalid IPv6 prefix {value}"))?;
    let segments = address.segments();
    Ok(Prefix64 {
        segments: [segments[0], segments[1], segments[2], segments[3]],
    })
}

fn compose_address(prefix: Prefix64, suffix: &str) -> Result<Ipv6Addr> {
    let suffix_address: Ipv6Addr = format!("::{suffix}")
        .parse()
        .with_context(|| format!("invalid legacy pool suffix {suffix:?}"))?;
    let suffix_segments = suffix_address.segments();
    Ok(Ipv6Addr::new(
        prefix.segments[0],
        prefix.segments[1],
        prefix.segments[2],
        prefix.segments[3],
        0,
        0,
        suffix_segments[6],
        suffix_segments[7],
    ))
}

fn random_suffix() -> Result<String> {
    let mut bytes = [0_u8; 4];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("RNG failure"))?;
    Ok(format!(
        "{:x}:{:x}",
        u16::from_be_bytes([bytes[0], bytes[1]]),
        u16::from_be_bytes([bytes[2], bytes[3]])
    ))
}

async fn discover_interface(prefix: &str) -> Result<String> {
    let output = Command::new("ip")
        .args(["-6", "route", "show", prefix])
        .output()
        .await
        .context("failed to run ip route for prefix interface discovery")?;
    if let Some(interface) = parse_route_interface(&output.stdout) {
        return Ok(interface);
    }

    let output = Command::new("ip")
        .args(["-6", "route", "show", "default"])
        .output()
        .await
        .context("failed to run ip route for default interface discovery")?;
    parse_route_interface(&output.stdout)
        .ok_or_else(|| anyhow::anyhow!("could not discover interface for routed prefix {prefix}"))
}

fn parse_route_interface(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output);
    let words: Vec<_> = text.split_whitespace().collect();
    words
        .windows(2)
        .find(|window| window[0] == "dev")
        .map(|window| window[1].to_string())
}

async fn ensure_host_address(interface: &str, address: Ipv6Addr) -> Result<()> {
    let output = Command::new("ip")
        .args(["-6", "-o", "addr", "show", "dev", interface])
        .output()
        .await
        .with_context(|| format!("failed to inspect IPv6 addresses on {interface}"))?;
    if address_list_contains(&output.stdout, address) {
        return Ok(());
    }

    let cidr = format!("{address}/128");
    let output = Command::new("ip")
        .args(["-6", "addr", "add", &cidr, "dev", interface])
        .output()
        .await
        .with_context(|| format!("failed to invoke ip while adding {cidr}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "failed to add {cidr} to {interface}: {}. Remote mode requires CAP_NET_ADMIN/root",
            stderr.trim()
        );
    }
    Ok(())
}

fn address_list_contains(output: &[u8], wanted: Ipv6Addr) -> bool {
    let text = String::from_utf8_lossy(output);
    text.lines().any(|line| {
        let words: Vec<_> = line.split_whitespace().collect();
        words.windows(2).any(|window| {
            window[0] == "inet6"
                && window[1]
                    .split('/')
                    .next()
                    .and_then(|value| value.parse::<Ipv6Addr>().ok())
                    == Some(wanted)
        })
    })
}

async fn discover_box_addresses(prefixes: &[String]) -> (String, String) {
    let parsed_prefixes: Vec<_> = prefixes
        .iter()
        .filter_map(|prefix| parse_prefix64(prefix).ok())
        .collect();
    let v6_addresses: Vec<Ipv6Addr> = global_addresses("-6")
        .await
        .into_iter()
        .filter_map(|address| address.parse().ok())
        .collect();
    let v6 = select_box_v6(&v6_addresses, &parsed_prefixes)
        .map(|address| address.to_string())
        .unwrap_or_default();
    let v4 = global_addresses("-4")
        .await
        .into_iter()
        .next()
        .unwrap_or_default();
    (v6, v4)
}

fn select_box_v6(addresses: &[Ipv6Addr], prefixes: &[Prefix64]) -> Option<Ipv6Addr> {
    addresses
        .iter()
        .copied()
        .find(|address| {
            is_eui64(*address) && prefixes.iter().any(|prefix| prefix.contains(*address))
        })
        .or_else(|| addresses.iter().copied().find(|address| is_eui64(*address)))
        .or_else(|| {
            addresses
                .iter()
                .copied()
                .find(|address| prefixes.iter().any(|prefix| prefix.contains(*address)))
        })
        .or_else(|| addresses.first().copied())
}

fn is_eui64(address: Ipv6Addr) -> bool {
    let octets = address.octets();
    octets[11] == 0xff && octets[12] == 0xfe
}

async fn global_addresses(family: &str) -> Vec<String> {
    let Ok(output) = Command::new("ip")
        .args([family, "-o", "addr", "show", "scope", "global"])
        .output()
        .await
    else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .flat_map(|line| {
            let words: Vec<_> = line.split_whitespace().collect();
            words
                .windows(2)
                .filter(|window| window[0] == "inet" || window[0] == "inet6")
                .filter_map(|window| window[1].split('/').next().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Default)]
struct SystemStats {
    cpu_pct: f64,
    mem_used_mb: u64,
    mem_total_mb: u64,
}

#[derive(Default)]
struct CpuSampler {
    previous: Option<(u64, u64)>,
}

impl CpuSampler {
    fn sample(&mut self) -> SystemStats {
        let current = read_cpu_ticks();
        let cpu_pct = match (self.previous, current) {
            (Some((old_busy, old_total)), Some((busy, total))) if total > old_total => {
                let busy_delta = busy.saturating_sub(old_busy);
                let total_delta = total.saturating_sub(old_total);
                100.0 * busy_delta as f64 / total_delta as f64
            }
            _ => 0.0,
        };
        if current.is_some() {
            self.previous = current;
        }
        let (used_kb, total_kb) = read_memory_kb().unwrap_or_default();
        SystemStats {
            cpu_pct: (cpu_pct * 100.0).round() / 100.0,
            mem_used_mb: used_kb / 1024,
            mem_total_mb: total_kb / 1024,
        }
    }
}

fn read_cpu_ticks() -> Option<(u64, u64)> {
    let data = fs::read_to_string("/proc/stat").ok()?;
    let line = data.lines().next()?;
    let values: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()
        .ok()?;
    if values.len() < 5 {
        return None;
    }
    let total: u64 = values.iter().sum();
    let idle = values[3].saturating_add(values[4]);
    Some((total.saturating_sub(idle), total))
}

fn read_memory_kb() -> Option<(u64, u64)> {
    let data = fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = None;
    let mut available = None;
    for line in data.lines() {
        if let Some(value) = line.strip_prefix("MemTotal:") {
            total = value.split_whitespace().next()?.parse().ok();
        } else if let Some(value) = line.strip_prefix("MemAvailable:") {
            available = value.split_whitespace().next()?.parse().ok();
        }
    }
    let total = total?;
    let available: u64 = available?;
    Some((total.saturating_sub(available), total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_suffix_composes_inside_prefix() -> Result<()> {
        let prefix = parse_prefix64("2001:db8:1234:5678::/64")?;
        assert_eq!(
            compose_address(prefix, "abcd:1234")?,
            "2001:db8:1234:5678::abcd:1234".parse::<Ipv6Addr>()?
        );
        assert_eq!(prefix.network_text(), "2001:db8:1234:5678");
        Ok(())
    }

    #[test]
    fn only_64_bit_prefixes_are_accepted() {
        assert!(parse_prefix64("2001:db8::/48").is_err());
        assert!(parse_prefix64("2001:db8::").is_err());
    }

    #[test]
    fn route_interface_parser_finds_dev() {
        assert_eq!(
            parse_route_interface(b"2001:db8::/64 dev ens3 proto kernel metric 256\n"),
            Some("ens3".to_string())
        );
    }

    #[test]
    fn address_parser_handles_compressed_ipv6() -> Result<()> {
        let wanted: Ipv6Addr = "2001:db8::abcd:1234".parse()?;
        assert!(address_list_contains(
            b"2: ens3    inet6 2001:db8::abcd:1234/128 scope global\n",
            wanted
        ));
        Ok(())
    }

    #[test]
    fn box_address_prefers_eui64_inside_routed_prefix() -> Result<()> {
        let prefix = parse_prefix64("2001:db8:1234:5678::/64")?;
        let random: Ipv6Addr = "2001:db8:1234:5678::abcd:1234".parse()?;
        let eui: Ipv6Addr = "2001:db8:1234:5678:dc12:34ff:fe56:789a".parse()?;
        let other_eui: Ipv6Addr = "2001:db8:9999:1:dc12:34ff:fe56:789a".parse()?;
        assert_eq!(
            select_box_v6(&[random, other_eui, eui], &[prefix]),
            Some(eui)
        );
        assert!(is_eui64(eui));
        assert!(!is_eui64(random));
        Ok(())
    }
}
