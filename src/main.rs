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

#[cfg(any(
    feature = "register",
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
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
use std::net::{IpAddr, SocketAddr};
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
#[cfg(feature = "https-proxy")]
use usque_rs::proxy::http::HttpsConfig;
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

#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
#[derive(Args, Clone)]
struct ProxyArgs {
    /// Expose a SOCKS5/SOCKS5h listener on this address. Repeat for multiple listeners.
    #[cfg(feature = "socks5-proxy")]
    #[arg(long, value_name = "ADDR")]
    socks5: Vec<SocketAddr>,

    /// Expose an explicitly unauthenticated SOCKS5/SOCKS5h listener.
    /// Only loopback, private/LAN, CGNAT, link-local, benchmark-lab, and IPv6 ULA addresses are accepted.
    #[cfg(feature = "socks5-proxy")]
    #[arg(long, value_name = "ADDR")]
    socks5_no_auth: Vec<SocketAddr>,

    /// Expose a plaintext HTTP proxy listener on this address.
    #[cfg(feature = "http-proxy")]
    #[arg(long, value_name = "ADDR")]
    http: Option<SocketAddr>,

    /// Expose a TLS-wrapped HTTP proxy listener on this address.
    #[cfg(feature = "https-proxy")]
    #[arg(long, value_name = "ADDR")]
    https: Option<SocketAddr>,

    /// Certificate chain for the HTTPS proxy listener.
    #[cfg(feature = "https-proxy")]
    #[arg(long, value_name = "PATH", requires = "https")]
    tls_cert: Option<String>,

    /// Private key for the HTTPS proxy listener.
    #[cfg(feature = "https-proxy")]
    #[arg(long, value_name = "PATH", requires = "https")]
    tls_key: Option<String>,

    #[arg(short, long)]
    username: Option<String>,

    #[arg(short = 'w', long)]
    password: Option<String>,

    /// Read proxy credentials as `username:password` from this file.
    #[arg(long, value_name = "PATH")]
    auth_file: Option<String>,

    #[command(flatten)]
    transport: L4TransportArgs,
}

#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
impl ProxyArgs {
    const fn listener_count(&self) -> usize {
        let mut count = 0;
        #[cfg(feature = "socks5-proxy")]
        {
            count += self.socks5.len() + self.socks5_no_auth.len();
        }
        #[cfg(feature = "http-proxy")]
        if self.http.is_some() {
            count += 1;
        }
        #[cfg(feature = "https-proxy")]
        if self.https.is_some() {
            count += 1;
        }
        count
    }
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

    /// Expose one shared WARP L4 session through one or more proxy listeners.
    #[cfg(any(
        feature = "http-proxy",
        feature = "https-proxy",
        feature = "socks5-proxy"
    ))]
    Proxy {
        #[command(flatten)]
        options: ProxyArgs,
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

            #[cfg(any(
                feature = "http-proxy",
                feature = "https-proxy",
                feature = "socks5-proxy"
            ))]
            Commands::Proxy { options } => cmd_proxy(&cli.config, options).await,
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

#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
fn validate_proxy_args(options: &ProxyArgs) -> Result<()> {
    if options.auth_file.is_some() {
        anyhow::ensure!(
            options.username.is_none() && options.password.is_none(),
            "--auth-file conflicts with --username/--password"
        );
    } else {
        validate_auth_pair(options.username.as_deref(), options.password.as_deref())?;
    }
    anyhow::ensure!(
        options.listener_count() > 0,
        "proxy requires at least one listener (--socks5, --http, or --https)"
    );

    #[cfg(feature = "socks5-proxy")]
    {
        let has_auth = options.auth_file.is_some()
            || (options.username.is_some() && options.password.is_some());
        if !options.socks5.is_empty() {
            anyhow::ensure!(
                has_auth,
                "--socks5 requires proxy authentication; use --socks5-no-auth for an explicit private no-auth listener"
            );
        }
        for bind in &options.socks5_no_auth {
            anyhow::ensure!(
                safe_no_auth_bind(bind.ip()),
                "--socks5-no-auth rejects globally routable, wildcard, multicast, and documentation-only bind address {}",
                bind.ip()
            );
        }
    }

    #[cfg(feature = "https-proxy")]
    match (
        options.https,
        options.tls_cert.as_deref(),
        options.tls_key.as_deref(),
    ) {
        (Some(_), Some(_), Some(_)) | (None, None, None) => {}
        (Some(_), _, _) => {
            anyhow::bail!("HTTPS proxy listener requires both --tls-cert and --tls-key");
        }
        (None, _, _) => {
            anyhow::bail!("--tls-cert/--tls-key require an --https listener");
        }
    }

    Ok(())
}

#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
async fn cmd_proxy(config_path: &str, options: ProxyArgs) -> Result<()> {
    validate_proxy_args(&options)?;
    let (username, password) = resolve_proxy_auth(&options)?;
    let l4 = create_l4(config_path, &options.transport).await?;
    let mut listeners = tokio::task::JoinSet::<Result<()>>::new();

    #[cfg(feature = "socks5-proxy")]
    for bind in options.socks5 {
        let l4 = l4.clone();
        let username = username.clone();
        let password = password.clone();
        listeners.spawn(async move {
            socks::serve(
                SocksConfig {
                    bind,
                    username,
                    password,
                },
                l4,
            )
            .await
        });
    }

    #[cfg(feature = "socks5-proxy")]
    for bind in options.socks5_no_auth {
        let l4 = l4.clone();
        listeners.spawn(async move {
            socks::serve(
                SocksConfig {
                    bind,
                    username: None,
                    password: None,
                },
                l4,
            )
            .await
        });
    }

    #[cfg(feature = "http-proxy")]
    if let Some(bind) = options.http {
        let l4 = l4.clone();
        let username = username.clone();
        let password = password.clone();
        listeners.spawn(async move {
            http_proxy::serve_plain(
                HttpConfig {
                    bind,
                    username,
                    password,
                },
                l4,
            )
            .await
        });
    }

    #[cfg(feature = "https-proxy")]
    if let Some(bind) = options.https {
        let l4 = l4.clone();
        let username = username.clone();
        let password = password.clone();
        let certificate = options
            .tls_cert
            .clone()
            .ok_or_else(|| anyhow::anyhow!("missing HTTPS certificate after validation"))?;
        let private_key = options
            .tls_key
            .clone()
            .ok_or_else(|| anyhow::anyhow!("missing HTTPS private key after validation"))?;
        listeners.spawn(async move {
            http_proxy::serve_tls(
                HttpConfig {
                    bind,
                    username,
                    password,
                },
                HttpsConfig {
                    certificate: certificate.into(),
                    private_key: private_key.into(),
                },
                l4,
            )
            .await
        });
    }

    let result = listeners
        .join_next()
        .await
        .ok_or_else(|| anyhow::anyhow!("proxy listener set unexpectedly empty"))?;
    listeners.abort_all();

    match result {
        Ok(Ok(())) => anyhow::bail!("proxy listener exited unexpectedly"),
        Ok(Err(error)) => Err(error),
        Err(error) => Err(error.into()),
    }
}

#[cfg(feature = "socks5-proxy")]
fn safe_no_auth_bind(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            a == 127
                || a == 10
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 198 && (b == 18 || b == 19))
        }
        std::net::IpAddr::V6(ip) => {
            let octets = ip.octets();
            ip.is_loopback()
                || (octets[0] & 0xfe) == 0xfc
                || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
        }
    }
}

#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
fn resolve_proxy_auth(options: &ProxyArgs) -> Result<(Option<String>, Option<String>)> {
    let Some(path) = options.auth_file.as_deref() else {
        return Ok((options.username.clone(), options.password.clone()));
    };
    let value = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read proxy auth file {path:?}"))?;
    let (username, password) = value
        .trim()
        .split_once(':')
        .context("proxy auth file must contain username:password")?;
    anyhow::ensure!(
        !username.is_empty() && !password.is_empty(),
        "proxy auth file username/password must be non-empty"
    );
    Ok((Some(username.to_owned()), Some(password.to_owned())))
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

    fn proxy_options(args: &[&str]) -> Result<ProxyArgs> {
        let cli = Cli::try_parse_from(args.iter().copied())?;
        match cli.command {
            Commands::Proxy { options } => Ok(options),
            #[cfg(feature = "register")]
            Commands::Register { .. } => anyhow::bail!("expected proxy command"),
            #[cfg(feature = "tun")]
            Commands::NativeTun { .. } => anyhow::bail!("expected proxy command"),
        }
    }

    #[test]
    fn proxy_requires_at_least_one_listener() -> Result<()> {
        let options = proxy_options(&["usque-rs", "proxy"])?;
        assert!(validate_proxy_args(&options).is_err());
        Ok(())
    }

    #[cfg(feature = "socks5-proxy")]
    #[test]
    fn authenticated_socks5_requires_auth() -> Result<()> {
        let options = proxy_options(&["usque-rs", "proxy", "--socks5", "127.0.0.1:1080"])?;
        assert!(validate_proxy_args(&options).is_err());

        let options = proxy_options(&[
            "usque-rs",
            "proxy",
            "--socks5",
            "[2001:db8::1]:1080",
            "--username",
            "user",
            "--password",
            "pass",
        ])?;
        assert_eq!(options.socks5, ["[2001:db8::1]:1080".parse()?]);
        assert!(validate_proxy_args(&options).is_ok());
        Ok(())
    }

    #[cfg(feature = "socks5-proxy")]
    #[test]
    fn passwordless_socks5_accepts_only_private_namespaces() -> Result<()> {
        for address in [
            "127.0.0.1:1080",
            "10.1.2.3:1080",
            "172.16.0.1:1080",
            "172.31.255.254:1080",
            "192.168.1.1:1080",
            "100.64.0.1:1080",
            "100.127.255.254:1080",
            "169.254.1.2:1080",
            "198.18.0.1:1080",
            "198.19.255.254:1080",
            "[::1]:1080",
            "[fc00::1]:1080",
            "[fd7a:115c:a1e0::1]:1080",
            "[fe80::1]:1080",
        ] {
            let options = proxy_options(&["usque-rs", "proxy", "--socks5-no-auth", address])?;
            assert!(
                validate_proxy_args(&options).is_ok(),
                "should permit {address}"
            );
        }

        for address in [
            "0.0.0.0:1080",
            "8.8.8.8:1080",
            "100.63.255.255:1080",
            "100.128.0.0:1080",
            "192.0.2.1:1080",
            "224.0.0.1:1080",
            "[::]:1080",
            "[2001:db8::1]:1080",
            "[2606:4700:4700::1111]:1080",
            "[ff02::1]:1080",
        ] {
            let options = proxy_options(&["usque-rs", "proxy", "--socks5-no-auth", address])?;
            assert!(
                validate_proxy_args(&options).is_err(),
                "should reject {address}"
            );
        }
        Ok(())
    }

    #[cfg(feature = "https-proxy")]
    #[test]
    fn https_listener_requires_tls_material() -> Result<()> {
        let options = proxy_options(&["usque-rs", "proxy", "--https", "127.0.0.1:8443"])?;
        assert!(validate_proxy_args(&options).is_err());
        Ok(())
    }

    #[cfg(all(
        feature = "socks5-proxy",
        feature = "http-proxy",
        feature = "https-proxy"
    ))]
    #[test]
    fn proxy_listeners_are_composable() -> Result<()> {
        let options = proxy_options(&[
            "usque-rs",
            "proxy",
            "--socks5",
            "127.0.0.1:1080",
            "--username",
            "user",
            "--password",
            "pass",
            "--http",
            "127.0.0.1:8000",
            "--https",
            "127.0.0.1:8443",
            "--tls-cert",
            "proxy.crt",
            "--tls-key",
            "proxy.key",
        ])?;
        assert_eq!(options.listener_count(), 3);
        assert!(validate_proxy_args(&options).is_ok());
        Ok(())
    }

    #[test]
    fn proxy_authentication_requires_a_complete_pair() {
        assert!(validate_auth_pair(None, None).is_ok());
        assert!(validate_auth_pair(Some("user"), Some("pass")).is_ok());
        assert!(validate_auth_pair(Some("user"), None).is_err());
        assert!(validate_auth_pair(None, Some("pass")).is_err());
    }
}
