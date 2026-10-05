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

//! usque-rs - MASQUE client for Cloudflare WARP.

#[cfg(feature = "register")]
use anyhow::Context;
use anyhow::Result;
#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
use clap::Args;
use clap::{Parser, Subcommand};
#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
use std::net::IpAddr;
#[cfg(any(
    feature = "tun",
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
use std::time::Duration;
#[cfg(any(feature = "register", feature = "tun"))]
use usque_rs::config;
#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
use usque_rs::l4::{L4Client, L4Config};
#[cfg(any(feature = "http-proxy", feature = "https-proxy"))]
use usque_rs::proxy::http::{self as http_proxy, HttpConfig};
#[cfg(feature = "socks5-proxy")]
use usque_rs::proxy::socks::{self, SocksConfig};
#[cfg(feature = "register")]
use usque_rs::register;
#[cfg(feature = "tun")]
use usque_rs::{tun_device, tunnel};

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

#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
#[derive(Args, Clone)]
struct L4TransportArgs {
    #[arg(short = 'P', long, default_value_t = 443)]
    connect_port: u16,
    #[arg(short = '6', long, default_value_t = false)]
    ipv6: bool,
    #[arg(short, long, default_value_t = 30)]
    keepalive_period: u64,
    #[arg(long)]
    source_ip: Option<IpAddr>,
    /// DNS resolver IPs reached over direct L4 TCP streams through WARP.
    #[arg(long = "dns-server", value_name = "IP")]
    dns_servers: Vec<IpAddr>,
}

#[cfg(feature = "tun")]
struct AddressSelection {
    use_ipv6_endpoint: bool,
    no_tunnel_ipv4: bool,
    no_tunnel_ipv6: bool,
}

#[cfg(feature = "tun")]
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
    /// Register a new client and enroll a device key.
    #[cfg(feature = "register")]
    Register {
        #[arg(short, long, default_value = "en_US")]
        locale: String,
        #[arg(short, long, default_value = "PC")]
        model: String,
        #[arg(short, long)]
        name: Option<String>,
        #[arg(long)]
        jwt: Option<String>,
    },

    /// Expose WARP as a native TUN device.
    #[cfg(feature = "tun")]
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

    /// Expose WARP as a direct-L4 TCP-only SOCKS5/SOCKS5h proxy.
    #[cfg(feature = "socks5-proxy")]
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
        transport: L4TransportArgs,
    },

    /// Expose WARP as a direct-L4 HTTP/1.1 forward proxy.
    #[cfg(feature = "http-proxy")]
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
        transport: L4TransportArgs,
    },

    /// Expose WARP as a direct-L4 HTTPS CONNECT proxy.
    #[cfg(feature = "https-proxy")]
    #[command(name = "https-proxy")]
    HttpsProxy {
        #[arg(short, long, default_value = "127.0.0.1")]
        bind: IpAddr,
        #[arg(short, long, default_value_t = 8000)]
        port: u16,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(short = 'w', long)]
        password: Option<String>,
        #[command(flatten)]
        transport: L4TransportArgs,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    #[cfg(not(any(
        feature = "register",
        feature = "tun",
        feature = "http-proxy",
        feature = "https-proxy",
        feature = "socks5-proxy"
    )))]
    anyhow::bail!("usque-rs was built without any capability feature");

    #[cfg(any(
        feature = "register",
        feature = "tun",
        feature = "http-proxy",
        feature = "https-proxy",
        feature = "socks5-proxy"
    ))]
    {
        env_logger::init();
        let cli = Cli::parse();

        match cli.command {
            #[cfg(feature = "register")]
            Commands::Register {
                locale,
                model,
                name,
                jwt,
            } => cmd_register(&cli.config, &locale, &model, name, jwt).await,

            #[cfg(feature = "tun")]
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

            #[cfg(feature = "socks5-proxy")]
            Commands::Socks {
                bind,
                port,
                username,
                password,
                transport,
            } => cmd_socks(&cli.config, bind, port, username, password, &transport).await,

            #[cfg(feature = "http-proxy")]
            Commands::HttpProxy {
                bind,
                port,
                username,
                password,
                transport,
            } => cmd_http_proxy(&cli.config, bind, port, username, password, &transport).await,

            #[cfg(feature = "https-proxy")]
            Commands::HttpsProxy {
                bind,
                port,
                username,
                password,
                transport,
            } => cmd_https_proxy(&cli.config, bind, port, username, password, &transport).await,
        }
    }
}

#[cfg(feature = "register")]
async fn cmd_register(
    config_path: &str,
    locale: &str,
    model: &str,
    device_name: Option<String>,
    jwt: Option<String>,
) -> Result<()> {
    if std::path::Path::new(config_path)
        .try_exists()
        .with_context(|| format!("failed to inspect config path {config_path}"))?
    {
        let response = tokio::task::spawn_blocking(|| {
            eprint!("Config already exists. Overwrite? (y/n): ");
            let mut response = String::new();
            std::io::stdin().read_line(&mut response)?;
            Ok::<_, std::io::Error>(response)
        })
        .await
        .context("overwrite prompt task failed")??;
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
    cfg.save_async(config_path).await?;
    log::info!("Config saved to {config_path}");
    Ok(())
}

#[cfg(feature = "tun")]
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

    let cfg = config::Config::load_async(config_path).await?;
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

#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
async fn create_l4(
    config_path: &str,
    transport: &L4TransportArgs,
) -> Result<std::sync::Arc<L4Client>> {
    L4Client::connect(
        config_path,
        &L4Config {
            connect_port: transport.connect_port,
            use_ipv6_endpoint: transport.ipv6,
            source_ip: transport.source_ip,
            keepalive_period: Duration::from_secs(transport.keepalive_period),
            dns_servers: transport.dns_servers.clone(),
        },
    )
    .await
}

#[cfg(feature = "socks5-proxy")]
async fn cmd_socks(
    config_path: &str,
    bind: IpAddr,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    transport: &L4TransportArgs,
) -> Result<()> {
    validate_auth_pair(username.as_deref(), password.as_deref())?;
    let l4 = create_l4(config_path, transport).await?;
    socks::serve(
        SocksConfig {
            bind: std::net::SocketAddr::new(bind, port),
            username,
            password,
        },
        l4,
    )
    .await
}

#[cfg(feature = "http-proxy")]
async fn cmd_http_proxy(
    config_path: &str,
    bind: IpAddr,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    transport: &L4TransportArgs,
) -> Result<()> {
    validate_auth_pair(username.as_deref(), password.as_deref())?;
    let l4 = create_l4(config_path, transport).await?;
    http_proxy::serve(
        HttpConfig {
            bind: std::net::SocketAddr::new(bind, port),
            username,
            password,
        },
        l4,
        true,
        cfg!(feature = "https-proxy"),
    )
    .await
}

#[cfg(feature = "https-proxy")]
async fn cmd_https_proxy(
    config_path: &str,
    bind: IpAddr,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    transport: &L4TransportArgs,
) -> Result<()> {
    validate_auth_pair(username.as_deref(), password.as_deref())?;
    let l4 = create_l4(config_path, transport).await?;
    http_proxy::serve(
        HttpConfig {
            bind: std::net::SocketAddr::new(bind, port),
            username,
            password,
        },
        l4,
        false,
        true,
    )
    .await
}

#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
fn validate_auth_pair(username: Option<&str>, password: Option<&str>) -> Result<()> {
    match (username, password) {
        (Some(_), Some(_)) | (None, None) => Ok(()),
        _ => anyhow::bail!("username and password must be supplied together"),
    }
}

#[cfg(all(
    test,
    any(
        feature = "http-proxy",
        feature = "https-proxy",
        feature = "socks5-proxy"
    )
))]
mod tests {
    use super::*;
    use clap::Parser;
    use std::net::Ipv4Addr;

    #[cfg(feature = "socks5-proxy")]
    #[test]
    fn socks_defaults_to_loopback() -> Result<()> {
        let cli = Cli::try_parse_from(["usque-rs", "socks"])?;
        let Commands::Socks { bind, port, .. } = cli.command else {
            anyhow::bail!("expected SOCKS command");
        };
        assert_eq!(bind, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(port, 1080);
        Ok(())
    }

    #[cfg(feature = "http-proxy")]
    #[test]
    fn http_proxy_defaults_to_loopback() -> Result<()> {
        let cli = Cli::try_parse_from(["usque-rs", "http-proxy"])?;
        let Commands::HttpProxy { bind, port, .. } = cli.command else {
            anyhow::bail!("expected HTTP proxy command");
        };
        assert_eq!(bind, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(port, 8000);
        Ok(())
    }

    #[cfg(feature = "https-proxy")]
    #[test]
    fn https_proxy_defaults_to_loopback() -> Result<()> {
        let cli = Cli::try_parse_from(["usque-rs", "https-proxy"])?;
        let Commands::HttpsProxy { bind, port, .. } = cli.command else {
            anyhow::bail!("expected HTTPS proxy command");
        };
        assert_eq!(bind, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(port, 8000);
        Ok(())
    }

    #[cfg(any(
        feature = "http-proxy",
        feature = "https-proxy",
        feature = "socks5-proxy"
    ))]
    #[test]
    fn proxy_authentication_requires_a_complete_pair() {
        assert!(validate_auth_pair(None, None).is_ok());
        assert!(validate_auth_pair(Some("user"), Some("pass")).is_ok());
        assert!(validate_auth_pair(Some("user"), None).is_err());
        assert!(validate_auth_pair(None, Some("pass")).is_err());
    }
}
