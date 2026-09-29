use anyhow::{Context, Result};

pub struct TunConfig {
    pub name: Option<String>,
    pub mtu: u32,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

/// Create the async TUN device with the requested MTU and offload support.
///
/// # Errors
///
/// Returns an error when the MTU is out of range or the device cannot be created.
pub fn create_tun(cfg: &TunConfig) -> Result<tun_rs::AsyncDevice> {
    let mtu = u16::try_from(cfg.mtu).context("TUN MTU does not fit u16")?;
    let mut builder = tun_rs::DeviceBuilder::new().mtu(mtu).offload(true);

    if let Some(ref name) = cfg.name {
        builder = builder.name(name.clone());
    }

    let dev = builder
        .build_async()
        .context("failed to create TUN device")?;

    log::info!(
        "TUN device created with Linux GSO/GRO offload: {}",
        dev.name()?
    );
    Ok(dev)
}

/// Configure addresses, MTU, and link state through rtnetlink.
///
/// # Errors
///
/// Returns an error when the device cannot be queried or any netlink operation fails.
pub async fn configure_tun(cfg: &TunConfig, dev: &tun_rs::AsyncDevice) -> Result<()> {
    use futures::stream::TryStreamExt;

    let tun_name = dev.name().context("failed to get TUN device name")?;

    let (connection, handle, _) =
        rtnetlink::new_connection().context("failed to create netlink connection")?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(tun_name.clone()).execute();
    let link = links
        .try_next()
        .await
        .context("failed to query link")?
        .context("TUN device not found via netlink")?;
    let link_index = link.header.index;

    handle
        .link()
        .set(
            rtnetlink::LinkUnspec::new_with_index(link_index)
                .mtu(cfg.mtu)
                .build(),
        )
        .execute()
        .await
        .context("failed to set MTU")?;
    log::info!("MTU set to {}", cfg.mtu);

    if let Some(ref ipv4) = cfg.ipv4 {
        let addr: std::net::Ipv4Addr = ipv4.parse().context("invalid IPv4 address in config")?;
        handle
            .address()
            .add(link_index, std::net::IpAddr::V4(addr), 32)
            .execute()
            .await
            .context("failed to add IPv4 address")?;
        log::info!("IPv4 address {addr}/32 added");
    }

    if let Some(ref ipv6) = cfg.ipv6 {
        let addr: std::net::Ipv6Addr = ipv6.parse().context("invalid IPv6 address in config")?;
        handle
            .address()
            .add(link_index, std::net::IpAddr::V6(addr), 128)
            .execute()
            .await
            .context("failed to add IPv6 address")?;
        log::info!("IPv6 address {addr}/128 added");
    }

    handle
        .link()
        .set(
            rtnetlink::LinkUnspec::new_with_index(link_index)
                .up()
                .build(),
        )
        .execute()
        .await
        .context("failed to bring link up")?;
    log::info!("Link {tun_name} is UP");

    Ok(())
}
