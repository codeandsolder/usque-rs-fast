#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )
)]

//! usque-rs - MASQUE (CONNECT-IP) client for Cloudflare WARP.

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use usque_rs::{
    config,
    proxy::{
        http::{self as http_proxy, HttpConfig},
        net::VirtualNet,
        session::{self as proxy_session, TransportConfig},
        socks::{self, SocksConfig},
    },
    proxy_pool::{
        core::{ChildTransport, ProxyAuth},
        offline::{self, OfflineConfig},
        remote::{self, RemoteConfig},
    },
    register, tun_device, tunnel,
};

#[derive(Parser)]
#[command(
    name = "usque-rs",
    about = "Unofficial Cloudflare WARP MASQUE client in Rust"
)]
struct Cli {
    #[arg(short, long, default_value = "config.json")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Args, Clone)]
struct ProxyTransportArgs {
    #[arg(short = 'P', long, default_value_t = 443)]
    connect_port: u16,
    #[arg(short = '6', long, default_value_t = false)]
    ipv6: bool,
    #[arg(short = 'F', long, default_value_t = false)]
    no_tunnel_ipv4: bool,
    #[arg(short = 'S', long, default_value_t = false)]
    no_tunnel_ipv6: bool,
    #[arg(short, long, default_value = "consumer-masque.cloudflareclient.com")]
    sni_address: String,
    #[arg(short, long, default_value_t = 30)]
    keepalive_period: u64,
    #[arg(short, long, default_value_t = 1280)]
    mtu: u32,
    #[arg(long)]
    source_ip: Option<IpAddr>,
}

struct AddressSelection {
    use_ipv6_endpoint: bool,
    no_tunnel_ipv4: bool,
    no_tunnel_ipv6: bool,
}

struct NativeTunOptions {
    connect_port: u16,
    addresses: AddressSelection,
    sni: String,
    keepalive_period: Duration,
    mtu: u32,
    no_iproute2: bool,
    interface_name: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Register a new client and enroll a device key
    Register {
        #[arg(short, long, default_value = "en_US")]
        locale: String,
        #[arg(short, long, default_value = "PC")]
        model: String,
        #[arg(short, long)]
        name: Option<String>,
        #[arg(long)]
        jwt: Option<String>,
        // Kept as a hidden no-op for CLI compatibility. Registering already
        // implies consent, so unattended registration must not prompt.
        #[arg(long = "accept-tos", hide = true)]
        accept_tos: bool,
    },
    /// Expose WARP as a native TUN device
    #[command(name = "nativetun")]
    NativeTun {
        #[arg(short = 'P', long, default_value_t = 443)]
        connect_port: u16,
        #[arg(short = '6', long, default_value_t = false)]
        ipv6: bool,
        #[arg(short = 'F', long, default_value_t = false)]
        no_tunnel_ipv4: bool,
        #[arg(short = 'S', long, default_value_t = false)]
        no_tunnel_ipv6: bool,
        #[arg(short, long, default_value = "consumer-masque.cloudflareclient.com")]
        sni_address: String,
        #[arg(short, long, default_value_t = 30)]
        keepalive_period: u64,
        #[arg(short, long, default_value_t = 1280)]
        mtu: u32,
        #[arg(short = 'I', long, default_value_t = false)]
        no_iproute2: bool,
        #[arg(short = 'n', long)]
        interface_name: Option<String>,
    },
    /// Expose WARP as a dual-stack SOCKS5/SOCKS5h proxy.
    Socks {
        #[arg(short, long, default_value = "127.0.0.1")]
        bind: IpAddr,
        #[arg(short, long, default_value_t = 1080)]
        port: u16,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(short = 'w', long)]
        password: Option<String>,
        #[command(flatten)]
        transport: ProxyTransportArgs,
    },
    /// Expose WARP as a streaming HTTP/1.1 proxy with CONNECT support.
    #[command(name = "http-proxy")]
    HttpProxy {
        #[arg(short, long, default_value = "127.0.0.1")]
        bind: IpAddr,
        #[arg(short, long, default_value_t = 8000)]
        port: u16,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(short = 'w', long)]
        password: Option<String>,
        #[command(flatten)]
        transport: ProxyTransportArgs,
    },
    /// Run multiple WARP identities as localhost SOCKS5 proxies without a control plane.
    PoolOffline {
        #[arg(long, default_value = "usque-pool")]
        dir: PathBuf,
        #[arg(long, default_value_t = 1)]
        count: usize,
        #[arg(long, default_value_t = 20_000)]
        base_port: u16,
        #[arg(long)]
        username: Option<String>,
        #[arg(short = 'w', long)]
        password: Option<String>,
        #[command(flatten)]
        transport: ProxyTransportArgs,
    },
    /// Run a routed proxy pool and report healthy identities to warp-orchestrator.
    PoolRemote {
        #[arg(long, default_value = "/opt/warp-pool")]
        dir: PathBuf,
        #[arg(long = "prefix")]
        prefixes: Vec<String>,
        #[arg(long)]
        interface: Option<String>,
        #[arg(long, default_value_t = 10)]
        slots_per_prefix: usize,
        #[arg(long, default_value_t = 20_000)]
        base_port: u16,
        #[arg(long)]
        orchestrator_url: Option<String>,
        #[arg(long, default_value = "/etc/warp-pool/config.json")]
        pool_config: PathBuf,
        #[arg(long, default_value = "/etc/warp-pool/psk")]
        psk_file: PathBuf,
        #[arg(long, default_value = "/etc/warp-pool/auth")]
        auth_file: PathBuf,
        #[arg(long)]
        hostname: Option<String>,
        #[command(flatten)]
        transport: ProxyTransportArgs,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Register {
            locale,
            model,
            name,
            jwt,
            accept_tos: _,
        } => cmd_register(&cli.config, &locale, &model, name, jwt).await,
        Commands::NativeTun {
            connect_port,
            ipv6,
            no_tunnel_ipv4,
            no_tunnel_ipv6,
            sni_address,
            keepalive_period,
            mtu,
            no_iproute2,
            interface_name,
        } => {
            cmd_nativetun(
                &cli.config,
                NativeTunOptions {
                    connect_port,
                    addresses: AddressSelection {
                        use_ipv6_endpoint: ipv6,
                        no_tunnel_ipv4,
                        no_tunnel_ipv6,
                    },
                    sni: sni_address,
                    keepalive_period: Duration::from_secs(keepalive_period),
                    mtu,
                    no_iproute2,
                    interface_name,
                },
            )
            .await
        }
        Commands::Socks {
            bind,
            port,
            username,
            password,
            transport,
        } => cmd_socks(&cli.config, bind, port, username, password, &transport).await,
        Commands::HttpProxy {
            bind,
            port,
            username,
            password,
            transport,
        } => cmd_http_proxy(&cli.config, bind, port, username, password, &transport).await,
        Commands::PoolOffline {
            dir,
            count,
            base_port,
            username,
            password,
            transport,
        } => cmd_pool_offline(dir, count, base_port, username, password, &transport).await,
        Commands::PoolRemote {
            dir,
            prefixes,
            interface,
            slots_per_prefix,
            base_port,
            orchestrator_url,
            pool_config,
            psk_file,
            auth_file,
            hostname,
            transport,
        } => {
            cmd_pool_remote(RemoteCommandOptions {
                dir,
                prefixes,
                interface,
                slots_per_prefix,
                base_port,
                orchestrator_url,
                pool_config,
                psk_file,
                auth_file,
                hostname,
                transport,
            })
            .await
        }
    }
}

async fn cmd_register(
    config_path: &str,
    locale: &str,
    model: &str,
    device_name: Option<String>,
    jwt: Option<String>,
) -> Result<()> {
    if let Ok(existing) = config::Config::load(config_path) {
        let _ = existing;
        eprint!("Config already exists. Overwrite? (y/n): ");
        let mut response = String::new();
        std::io::stdin().read_line(&mut response)?;
        if response.trim() != "y" {
            log::info!("Aborted.");
            return Ok(());
        }
    }

    log::info!("Registering with locale={locale} model={model}");
    let account_data = register::register(model, locale, jwt.as_deref()).await?;
    log::info!("Registration successful, enrolling device key...");

    let (priv_key_der, pub_key_der) = register::generate_ec_keypair()?;
    let updated = register::enroll_key(&account_data, &pub_key_der, device_name.as_deref()).await?;

    let cfg = config::Config::from_account_data(&updated, &account_data.token, &priv_key_der)?;
    cfg.save(config_path)?;
    log::info!("Config saved to {config_path}");
    Ok(())
}

async fn cmd_nativetun(config_path: &str, options: NativeTunOptions) -> Result<()> {
    let NativeTunOptions {
        connect_port,
        addresses:
            AddressSelection {
                use_ipv6_endpoint,
                no_tunnel_ipv4,
                no_tunnel_ipv6,
            },
        sni,
        keepalive_period,
        mtu,
        no_iproute2,
        interface_name,
    } = options;
    if keepalive_period.is_zero() {
        anyhow::bail!("keepalive period must be greater than zero");
    }
    if mtu != 1280 {
        log::warn!(
            "MTU {mtu} differs from the supported/default 1280; packet loss or PMTU issues may occur"
        );
    }

    let cfg = config::Config::load(config_path)?;
    eprintln!("Config loaded from {config_path}");

    let endpoint_ip: std::net::IpAddr = if use_ipv6_endpoint {
        cfg.endpoint_v6.parse()?
    } else {
        cfg.endpoint_v4.parse()?
    };
    let endpoint = std::net::SocketAddr::new(endpoint_ip, connect_port);

    let tun_cfg = tun_device::TunConfig {
        name: interface_name,
        mtu,
        ipv4: if no_tunnel_ipv4 {
            None
        } else {
            Some(cfg.ipv4.clone())
        },
        ipv6: if no_tunnel_ipv6 {
            None
        } else {
            Some(cfg.ipv6.clone())
        },
    };
    let tun_dev = tun_device::create_tun(&tun_cfg)?;

    if no_iproute2 {
        eprintln!("Skipping address setup (--no-iproute2)");
    } else {
        tun_device::configure_tun(&tun_cfg, &tun_dev).await?;
    }

    let tunnel_cfg = tunnel::TunnelConfig {
        endpoint,
        sni,
        keepalive_period,
        mtu,
    };

    tunnel::maintain_tunnel(&cfg, &tunnel_cfg, tun_dev).await
}

async fn cmd_socks(
    config_path: &str,
    bind: IpAddr,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    transport: &ProxyTransportArgs,
) -> Result<()> {
    validate_auth_pair(username.as_deref(), password.as_deref())?;
    let net = create_proxy_net(config_path, transport).await?;
    socks::serve(
        SocksConfig {
            bind: SocketAddr::new(bind, port),
            username,
            password,
        },
        net,
    )
    .await
}

async fn cmd_http_proxy(
    config_path: &str,
    bind: IpAddr,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    transport: &ProxyTransportArgs,
) -> Result<()> {
    validate_auth_pair(username.as_deref(), password.as_deref())?;
    let net = create_proxy_net(config_path, transport).await?;
    http_proxy::serve(
        HttpConfig {
            bind: SocketAddr::new(bind, port),
            username,
            password,
        },
        net,
    )
    .await
}

async fn cmd_pool_offline(
    dir: PathBuf,
    count: usize,
    base_port: u16,
    username: Option<String>,
    password: Option<String>,
    transport: &ProxyTransportArgs,
) -> Result<()> {
    validate_auth_pair(username.as_deref(), password.as_deref())?;
    let auth = username
        .zip(password)
        .map(|(username, password)| ProxyAuth { username, password });
    offline::run(OfflineConfig {
        root: dir,
        count,
        base_port,
        port_stride: 1_000,
        auth,
        transport: child_transport(transport),
        registration_delay: Duration::from_secs(8),
    })
    .await
}

struct RemoteCommandOptions {
    dir: PathBuf,
    prefixes: Vec<String>,
    interface: Option<String>,
    slots_per_prefix: usize,
    base_port: u16,
    orchestrator_url: Option<String>,
    pool_config: PathBuf,
    psk_file: PathBuf,
    auth_file: PathBuf,
    hostname: Option<String>,
    transport: ProxyTransportArgs,
}

#[derive(Debug, Default, Deserialize)]
struct LegacyPoolConfig {
    #[serde(default)]
    orchestrator_url: Option<String>,
    #[serde(default)]
    psk: Option<String>,
    #[serde(default)]
    prefixes: Vec<String>,
}

async fn cmd_pool_remote(options: RemoteCommandOptions) -> Result<()> {
    let RemoteCommandOptions {
        dir,
        mut prefixes,
        interface,
        slots_per_prefix,
        base_port,
        orchestrator_url,
        pool_config,
        psk_file,
        auth_file,
        hostname,
        transport,
    } = options;
    let legacy = load_legacy_pool_config(&pool_config)?;

    if prefixes.is_empty() {
        if !legacy.prefixes.is_empty() {
            prefixes = legacy.prefixes;
        } else {
            prefixes = csv_env("PREFIXES_CSV");
        }
    }

    let orchestrator_url = orchestrator_url
        .or_else(|| std::env::var("ORCHESTRATOR_URL").ok())
        .or(legacy.orchestrator_url)
        .unwrap_or_else(|| "https://orchestrator.onhir.com".to_string());

    let psk = match legacy.psk.filter(|value| !value.is_empty()) {
        Some(value) => value,
        None => std::fs::read_to_string(&psk_file)?.trim().to_string(),
    };
    let auth = read_proxy_auth(&auth_file)?;
    let hostname = hostname
        .or_else(|| std::env::var("VPS_ID").ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".to_string());
    remote::run(RemoteConfig {
        root: dir,
        prefixes,
        interface,
        slots_per_prefix,
        topup_count: 10,
        stale_limit: 5,
        base_port,
        port_stride: 1_000,
        auth,
        transport: child_transport(&transport),
        registration_delay: Duration::from_secs(8),
        probe_wait: Duration::from_secs(8),
        heartbeat_interval: Duration::from_secs(15),
        register_interval: Duration::from_secs(180),
        drift_interval: Duration::from_secs(15),
        orchestrator_url,
        psk,
        hostname,
    })
    .await
}

async fn create_proxy_net(
    config_path: &str,
    transport: &ProxyTransportArgs,
) -> Result<Arc<VirtualNet>> {
    proxy_session::connect(
        config_path,
        &TransportConfig {
            connect_port: transport.connect_port,
            use_ipv6_endpoint: transport.ipv6,
            no_tunnel_ipv4: transport.no_tunnel_ipv4,
            no_tunnel_ipv6: transport.no_tunnel_ipv6,
            sni: transport.sni_address.clone(),
            keepalive_period: Duration::from_secs(transport.keepalive_period),
            mtu: transport.mtu,
            source_ip: transport.source_ip,
        },
    )
    .await
}

fn child_transport(transport: &ProxyTransportArgs) -> ChildTransport {
    ChildTransport {
        connect_port: transport.connect_port,
        sni: transport.sni_address.clone(),
        keepalive_period: Duration::from_secs(transport.keepalive_period),
        mtu: transport.mtu,
        no_tunnel_ipv4: transport.no_tunnel_ipv4,
        no_tunnel_ipv6: transport.no_tunnel_ipv6,
        use_ipv6_endpoint: transport.ipv6,
    }
}

fn load_legacy_pool_config(path: &Path) -> Result<LegacyPoolConfig> {
    if !path.exists() {
        return Ok(LegacyPoolConfig::default());
    }
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid pool config {}: {error}", path.display()))
}

fn csv_env(name: &str) -> Vec<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn read_proxy_auth(path: &Path) -> Result<ProxyAuth> {
    let value = std::fs::read_to_string(path)?;
    let (username, password) = value
        .trim()
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("proxy auth file must contain username:password"))?;
    if username.is_empty() || password.is_empty() {
        anyhow::bail!("proxy auth username/password must not be empty");
    }
    Ok(ProxyAuth {
        username: username.to_string(),
        password: password.to_string(),
    })
}

fn validate_auth_pair(username: Option<&str>, password: Option<&str>) -> Result<()> {
    match (username, password) {
        (Some(_), Some(_)) | (None, None) => Ok(()),
        _ => anyhow::bail!("username and password must be supplied together"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::net::Ipv4Addr;

    #[test]
    fn proxy_commands_default_to_loopback() -> Result<()> {
        let socks = Cli::try_parse_from(["usque-rs", "socks"])?;
        let Commands::Socks { bind, port, .. } = socks.command else {
            anyhow::bail!("expected SOCKS command");
        };
        assert_eq!(bind, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(port, 1080);

        let http = Cli::try_parse_from(["usque-rs", "http-proxy"])?;
        let Commands::HttpProxy { bind, port, .. } = http.command else {
            anyhow::bail!("expected HTTP proxy command");
        };
        assert_eq!(bind, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(port, 8000);
        Ok(())
    }

    #[test]
    fn proxy_authentication_requires_a_complete_pair() {
        assert!(validate_auth_pair(None, None).is_ok());
        assert!(validate_auth_pair(Some("user"), Some("pass")).is_ok());
        assert!(validate_auth_pair(Some("user"), None).is_err());
        assert!(validate_auth_pair(None, Some("pass")).is_err());
    }

    #[test]
    fn offline_pool_defaults_to_local_control_plane_free_layout() -> Result<()> {
        let cli = Cli::try_parse_from(["usque-rs", "pool-offline"])?;
        let Commands::PoolOffline {
            dir,
            count,
            base_port,
            username,
            password,
            ..
        } = cli.command
        else {
            anyhow::bail!("expected offline pool command");
        };
        assert_eq!(dir, PathBuf::from("usque-pool"));
        assert_eq!(count, 1);
        assert_eq!(base_port, 20_000);
        assert!(username.is_none());
        assert!(password.is_none());
        Ok(())
    }

    #[test]
    fn remote_pool_requires_prefixes_at_runtime_not_parse_time() -> Result<()> {
        let cli = Cli::try_parse_from(["usque-rs", "pool-remote"])?;
        let Commands::PoolRemote {
            prefixes,
            slots_per_prefix,
            base_port,
            orchestrator_url,
            pool_config,
            ..
        } = cli.command
        else {
            anyhow::bail!("expected remote pool command");
        };
        assert!(prefixes.is_empty());
        assert_eq!(slots_per_prefix, 10);
        assert_eq!(base_port, 20_000);
        assert!(orchestrator_url.is_none());
        assert_eq!(pool_config, PathBuf::from("/etc/warp-pool/config.json"));
        Ok(())
    }

    #[test]
    fn legacy_pool_config_is_compatible() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.json");
        std::fs::write(
            &path,
            br#"{
              "version": 1,
              "orchestrator_url": "https://orchestrator.example",
              "psk": "legacy-psk",
              "prefixes": ["2001:db8:1:2::/64"],
              "socks_user": "ignored-by-rust-auth-file"
            }"#,
        )?;
        let parsed = load_legacy_pool_config(&path)?;
        assert_eq!(
            parsed.orchestrator_url.as_deref(),
            Some("https://orchestrator.example")
        );
        assert_eq!(parsed.psk.as_deref(), Some("legacy-psk"));
        assert_eq!(parsed.prefixes, ["2001:db8:1:2::/64"]);
        Ok(())
    }
}
