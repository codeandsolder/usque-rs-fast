use anyhow::{Context, Result};

pub struct TunConfig {
    pub name: Option<String>,
    pub mtu: u32,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

/// Create and configure the async TUN device.
///
/// Linux initial address setup uses the tun-rs direct ioctl path, avoiding a
/// separate netlink stack. Set `configure_addresses` to false when callers
/// want to manage interface addresses themselves.
///
/// # Errors
///
/// Returns an error when the MTU or configured addresses are invalid, or the
/// device cannot be created/configured.
pub fn create_tun(cfg: &TunConfig, configure_addresses: bool) -> Result<tun_rs::AsyncDevice> {
    let mtu = u16::try_from(cfg.mtu).context("TUN MTU does not fit u16")?;
    let mut builder = tun_rs::DeviceBuilder::new().mtu(mtu).offload(true);

    if let Some(ref name) = cfg.name {
        builder = builder.name(name.clone());
    }

    if configure_addresses {
        if let Some(ref ipv4) = cfg.ipv4 {
            let address: std::net::Ipv4Addr =
                ipv4.parse().context("invalid IPv4 address in config")?;
            builder = builder.ipv4(address, 32, None::<std::net::Ipv4Addr>);
        }
        if let Some(ref ipv6) = cfg.ipv6 {
            let address: std::net::Ipv6Addr =
                ipv6.parse().context("invalid IPv6 address in config")?;
            builder = builder.ipv6(address, 128);
        }
    }

    let dev = builder
        .build_async()
        .context("failed to create/configure TUN device")?;

    log::info!(
        "TUN device created with Linux GSO/GRO offload: {}",
        dev.name()?
    );
    Ok(dev)
}
