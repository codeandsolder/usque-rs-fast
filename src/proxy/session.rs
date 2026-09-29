use crate::{config, packet_session::PacketSessionConfig, MasquePacketStream};
use anyhow::{Context, Result};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use super::net::VirtualNet;

#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub connect_port: u16,
    pub use_ipv6_endpoint: bool,
    pub no_tunnel_ipv4: bool,
    pub no_tunnel_ipv6: bool,
    pub sni: String,
    pub keepalive_period: Duration,
    pub mtu: u32,
    pub source_ip: Option<IpAddr>,
}

/// Create the userspace WARP network used by the proxy frontends.
///
/// source_ip controls the outer MASQUE UDP socket. It is intentionally
/// independent from the WARP-assigned inner IPv4/IPv6 addresses; remote pool
/// mode uses this to pin each identity to a distinct routed host /128.
///
/// # Errors
/// Returns an error for invalid address-family combinations, malformed WARP
/// configuration, MASQUE connection failures, or userspace stack setup errors.
pub async fn connect(config_path: &str, transport: &TransportConfig) -> Result<Arc<VirtualNet>> {
    validate(transport)?;

    let config = config::Config::load(config_path)?;
    let endpoint_ip: IpAddr = if transport.use_ipv6_endpoint {
        config.endpoint_v6.parse()?
    } else {
        config.endpoint_v4.parse()?
    };
    let endpoint = SocketAddr::new(endpoint_ip, transport.connect_port);

    if let Some(source_ip) = transport.source_ip {
        match (source_ip, endpoint_ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {}
            _ => anyhow::bail!(
                "source IP {source_ip} and MASQUE endpoint {endpoint_ip} use different address families"
            ),
        }
    }

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
            bind: transport
                .source_ip
                .map(|source_ip| SocketAddr::new(source_ip, 0)),
            sni: transport.sni.clone(),
            keepalive_period: transport.keepalive_period,
            mtu: transport.mtu,
        },
    )
    .await?;

    let mtu = usize::try_from(transport.mtu)
        .map_err(|_| anyhow::anyhow!("MTU does not fit usize: {}", transport.mtu))?;
    VirtualNet::start(packet_stream, local_v4, local_v6, mtu).map_err(Into::into)
}

fn validate(transport: &TransportConfig) -> Result<()> {
    if transport.keepalive_period.is_zero() {
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
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_disabled_inner_families() {
        let cfg = TransportConfig {
            connect_port: 443,
            use_ipv6_endpoint: false,
            no_tunnel_ipv4: true,
            no_tunnel_ipv6: true,
            sni: "example.invalid".to_string(),
            keepalive_period: Duration::from_secs(30),
            mtu: 1280,
            source_ip: None,
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn parses_configured_addresses_with_prefix_lengths() -> Result<()> {
        assert_eq!(
            parse_assigned_ipv4("172.16.0.2/32")?,
            Ipv4Addr::new(172, 16, 0, 2)
        );
        assert_eq!(
            parse_assigned_ipv6("2606:4700:110::2/128")?,
            "2606:4700:110::2".parse::<Ipv6Addr>()?
        );
        Ok(())
    }
}
