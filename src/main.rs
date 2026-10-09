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
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
use anyhow::Context;
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
#[cfg(any(
    feature = "tun",
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
use std::net::IpAddr;
#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
use std::net::SocketAddr;
#[cfg(any(
    feature = "tun",
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
use std::time::Duration;
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
#[cfg(any(
    feature = "tun",
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
use usque_rs::{
    config,
    registration_store::{RegistrationOptions, RegistrationStore},
};
#[cfg(feature = "tun")]
use usque_rs::{tun_device, tunnel};

#[derive(Parser)]
#[command(
    name = "usque-rs",
    about = "Unofficial Cloudflare WARP MASQUE client in Rust"
)]
struct Cli {
    #[command(flatten)]
    registration: RegistrationArgs,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Args, Clone)]
struct RegistrationArgs {
    /// Directory containing one enrolled MASQUE identity per selected source IP.
    #[arg(long, default_value = "registrations", global = true)]
    registration_store: std::path::PathBuf,

    /// Replace the registration for the selected source IP before connecting.
    #[arg(long, default_value_t = false, global = true)]
    reregister: bool,

    #[arg(long, default_value = "en_US", global = true)]
    registration_locale: String,

    #[arg(long, default_value = "PC", global = true)]
    registration_model: String,

    #[arg(long, global = true)]
    registration_name: Option<String>,

    #[arg(long, global = true)]
    registration_jwt: Option<String>,
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
    source_ip: Option<IpAddr>,
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

    /// Expose a private open SOCKS5/SOCKS5h listener; no credentials are required and presented credentials are ignored.
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
    /// Expose WARP as a native TUN device.
    #[cfg(feature = "tun")]
    #[command(name = "nativetun")]
    NativeTun {
        #[arg(short = 'P', long, default_value_t = 443)]
        connect_port: u16,
        #[arg(short = '6', long, default_value_t = false)]
        ipv6: bool,
        /// Bind registration and the outer MASQUE connection to this source IP.
        #[arg(long)]
        source_ip: Option<IpAddr>,
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
        options: Box<ProxyArgs>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    #[cfg(not(any(
        feature = "tun",
        feature = "http-proxy",
        feature = "https-proxy",
        feature = "socks5-proxy"
    )))]
    anyhow::bail!("usque-rs was built without any capability feature");

    #[cfg(any(
        feature = "tun",
        feature = "http-proxy",
        feature = "https-proxy",
        feature = "socks5-proxy"
    ))]
    {
        env_logger::init();
        let cli = Cli::parse();
        let registration = cli.registration;

        match cli.command {
            #[cfg(feature = "tun")]
            Commands::NativeTun {
                connect_port,
                ipv6,
                source_ip,
                no_tunnel_ipv4,
                no_tunnel_ipv6,
                sni_address,
                keepalive_period,
                mtu,
                no_iproute2,
                interface_name,
            } => {
                cmd_nativetun(
                    &registration,
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
                        source_ip,
                    },
                )
                .await
            }

            #[cfg(any(
                feature = "http-proxy",
                feature = "https-proxy",
                feature = "socks5-proxy"
            ))]
            Commands::Proxy { options } => cmd_proxy(&registration, *options).await,
        }
    }
}

#[cfg(any(
    feature = "tun",
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
fn validate_source_family(source_ip: Option<IpAddr>, use_ipv6_endpoint: bool) -> Result<()> {
    if let Some(source_ip) = source_ip {
        anyhow::ensure!(
            source_ip.is_ipv6() == use_ipv6_endpoint,
            "source IP {source_ip} does not match the selected MASQUE endpoint family; use --ipv6 for an IPv6 source"
        );
    }
    Ok(())
}

#[cfg(any(
    feature = "tun",
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
async fn resolve_registration(
    args: &RegistrationArgs,
    source_ip: Option<IpAddr>,
) -> Result<config::Config> {
    let store = RegistrationStore::new(args.registration_store.clone());
    let options = RegistrationOptions {
        locale: args.registration_locale.clone(),
        model: args.registration_model.clone(),
        device_name: args.registration_name.clone(),
        jwt: args.registration_jwt.clone(),
        reregister: args.reregister,
    };
    store.resolve(source_ip, &options).await
}

#[cfg(feature = "tun")]
async fn cmd_nativetun(registration: &RegistrationArgs, options: NativeTunOptions) -> Result<()> {
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
        source_ip,
    } = options;
    if keepalive_period.is_zero() {
        anyhow::bail!("keepalive period must be greater than zero");
    }
    if mtu != 1280 {
        log::warn!(
            "MTU {mtu} differs from the supported/default 1280; packet loss or PMTU issues may occur"
        );
    }

    validate_source_family(source_ip, use_ipv6_endpoint)?;
    let cfg = resolve_registration(registration, source_ip).await?;

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
    let tun_dev = tun_device::create_tun(&tun_cfg, !no_iproute2)?;

    if no_iproute2 {
        eprintln!("Skipping address setup (--no-iproute2)");
    }

    let tunnel_cfg = tunnel::TunnelConfig {
        endpoint,
        sni,
        keepalive_period,
        mtu,
        source_ip,
    };
    tunnel::maintain_tunnel(&cfg, &tunnel_cfg, tun_dev).await
}

#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
async fn create_l4(
    config: config::Config,
    transport: &L4TransportArgs,
) -> Result<std::sync::Arc<L4Client>> {
    L4Client::connect(
        config,
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
                "--socks5 requires proxy authentication; use --socks5-no-auth for an explicit private open listener"
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
async fn cmd_proxy(registration: &RegistrationArgs, options: ProxyArgs) -> Result<()> {
    validate_proxy_args(&options)?;
    let (username, password) = resolve_proxy_auth(&options)?;
    validate_source_family(options.transport.source_ip, options.transport.ipv6)?;
    let config = resolve_registration(registration, options.transport.source_ip).await?;
    let l4 = create_l4(config, &options.transport).await?;
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
            Commands::Proxy { options } => Ok(*options),
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

#[cfg(all(
    test,
    any(
        feature = "tun",
        feature = "http-proxy",
        feature = "https-proxy",
        feature = "socks5-proxy"
    )
))]
mod registration_lifecycle_tests {
    use super::*;

    #[test]
    fn explicit_source_must_match_selected_endpoint_family() -> Result<()> {
        assert!(validate_source_family(Some("192.0.2.1".parse()?), false).is_ok());
        assert!(validate_source_family(Some("2001:db8::1".parse()?), true).is_ok());
        assert!(validate_source_family(Some("192.0.2.1".parse()?), true).is_err());
        assert!(validate_source_family(Some("2001:db8::1".parse()?), false).is_err());
        assert!(validate_source_family(None, false).is_ok());
        assert!(validate_source_family(None, true).is_ok());
        Ok(())
    }
}
