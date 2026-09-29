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

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use usque_rs::{
    config,
    packet_session::PacketSessionConfig,
    proxy::{
        http::{self as http_proxy, HttpConfig},
        net::VirtualNet,
        socks::{self, SocksConfig},
    },
    register, tun_device, tunnel, MasquePacketStream,
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
    /// Expose WARP as a dual-stack SOCKS5/SOCKS5h TCP proxy.
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
                connect_port,
                ipv6,
                no_tunnel_ipv4,
                no_tunnel_ipv6,
                &sni_address,
                Duration::from_secs(keepalive_period),
                mtu,
                no_iproute2,
                interface_name,
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

#[allow(clippy::too_many_arguments)]
async fn cmd_nativetun(
    config_path: &str,
    connect_port: u16,
    use_ipv6: bool,
    no_tunnel_ipv4: bool,
    no_tunnel_ipv6: bool,
    sni: &str,
    keepalive_period: Duration,
    mtu: u32,
    no_iproute2: bool,
    interface_name: Option<String>,
) -> Result<()> {
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

    let endpoint_ip: std::net::IpAddr = if use_ipv6 {
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
        setup_addresses: !no_iproute2,
    };
    let tun_dev = tun_device::create_tun(&tun_cfg)?;

    if no_iproute2 {
        eprintln!("Skipping address setup (--no-iproute2)");
    } else {
        tun_device::configure_tun(&tun_cfg, &tun_dev).await?;
    }

    let tunnel_cfg = tunnel::TunnelConfig {
        endpoint,
        sni: sni.to_string(),
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
    validate_auth_pair(&username, &password)?;
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
    validate_auth_pair(&username, &password)?;
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

async fn create_proxy_net(
    config_path: &str,
    transport: &ProxyTransportArgs,
) -> Result<Arc<VirtualNet>> {
    if transport.keepalive_period == 0 {
        anyhow::bail!("keepalive period must be greater than zero");
    }
    if transport.no_tunnel_ipv4 && transport.no_tunnel_ipv6 {
        anyhow::bail!("at least one tunnel address family must be enabled");
    }
    if transport.mtu != 1280 {
        log::warn!(
            "MTU {} differs from the supported/default 1280; packet loss or PMTU issues may occur",
            transport.mtu
        );
    }

    let config = config::Config::load(config_path)?;
    let endpoint_ip: IpAddr = if transport.ipv6 {
        config.endpoint_v6.parse()?
    } else {
        config.endpoint_v4.parse()?
    };
    let endpoint = SocketAddr::new(endpoint_ip, transport.connect_port);

    let local_v4 = if transport.no_tunnel_ipv4 {
        None
    } else {
        Some(parse_assigned_ipv4(&config.ipv4)?)
    };
    let local_v6 = if transport.no_tunnel_ipv6 {
        None
    } else {
        Some(parse_assigned_ipv6(&config.ipv6)?)
    };

    let packet_stream = MasquePacketStream::connect(
        Arc::new(config),
        PacketSessionConfig {
            endpoint,
            bind: None,
            sni: transport.sni_address.clone(),
            keepalive_period: Duration::from_secs(transport.keepalive_period),
            mtu: transport.mtu,
        },
    )
    .await?;

    VirtualNet::start(packet_stream, local_v4, local_v6, transport.mtu as usize).map_err(Into::into)
}

fn parse_assigned_ipv4(value: &str) -> Result<Ipv4Addr> {
    value
        .split('/')
        .next()
        .unwrap_or(value)
        .parse()
        .with_context(|| format!("invalid configured WARP IPv4 address {value:?}"))
}

fn parse_assigned_ipv6(value: &str) -> Result<Ipv6Addr> {
    value
        .split('/')
        .next()
        .unwrap_or(value)
        .parse()
        .with_context(|| format!("invalid configured WARP IPv6 address {value:?}"))
}

fn validate_auth_pair(username: &Option<String>, password: &Option<String>) -> Result<()> {
    match (username, password) {
        (Some(_), Some(_)) | (None, None) => Ok(()),
        _ => anyhow::bail!("username and password must be supplied together"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn proxy_commands_default_to_loopback() {
        let socks = Cli::try_parse_from(["usque-rs", "socks"]).expect("SOCKS defaults parse");
        match socks.command {
            Commands::Socks { bind, port, .. } => {
                assert_eq!(bind, IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert_eq!(port, 1080);
            }
            _ => panic!("expected SOCKS command"),
        }

        let http = Cli::try_parse_from(["usque-rs", "http-proxy"]).expect("HTTP defaults parse");
        match http.command {
            Commands::HttpProxy { bind, port, .. } => {
                assert_eq!(bind, IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert_eq!(port, 8000);
            }
            _ => panic!("expected HTTP proxy command"),
        }
    }

    #[test]
    fn proxy_authentication_requires_a_complete_pair() {
        assert!(validate_auth_pair(&None, &None).is_ok());
        assert!(validate_auth_pair(&Some("user".to_string()), &Some("pass".to_string())).is_ok());
        assert!(validate_auth_pair(&Some("user".to_string()), &None).is_err());
        assert!(validate_auth_pair(&None, &Some("pass".to_string())).is_err());
    }
}
