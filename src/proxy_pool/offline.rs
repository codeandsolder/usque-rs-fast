use super::{
    core::{
        ChildSpec, ChildTransport, ProxyAuth, SlotKey, Supervisor, port_for, wait_for_shutdown,
    },
    state::identity_config_path,
};
use anyhow::{Context, Result};
use serde::Serialize;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct OfflineConfig {
    pub root: PathBuf,
    pub count: usize,
    pub base_port: u16,
    pub port_stride: u16,
    pub auth: Option<ProxyAuth>,
    pub transport: ChildTransport,
    pub registration_delay: Duration,
}

#[derive(Debug, Serialize)]
struct InventoryEntry {
    group: usize,
    slot: usize,
    config: PathBuf,
    listen: String,
}

/// Run a local-only WARP proxy pool until shutdown.
///
/// # Errors
/// Returns an error for identity registration, child lifecycle, filesystem, or signal failures.
pub async fn run(config: OfflineConfig) -> Result<()> {
    if config.count == 0 {
        anyhow::bail!("offline pool count must be greater than zero");
    }
    fs::create_dir_all(&config.root)?;

    let mut supervisor = Supervisor::new(config.root.clone())?;
    let mut specs = Vec::with_capacity(config.count);
    let mut inventory = Vec::with_capacity(config.count);

    for slot in 0..config.count {
        let created = supervisor.ensure_identity(0, slot).await?;
        if created && !config.registration_delay.is_zero() && slot + 1 < config.count {
            tokio::time::sleep(config.registration_delay).await;
        }

        let port = port_for(config.base_port, config.port_stride, 0, slot)?;
        let spec = ChildSpec {
            group: 0,
            slot,
            bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            source_ip: None,
            port,
            auth: config.auth.clone(),
            transport: config.transport.clone(),
        };
        let pid = supervisor.start(&spec).await?;
        log::info!("offline proxy slot={slot} listening on 127.0.0.1:{port} pid={pid}");
        inventory.push(InventoryEntry {
            group: 0,
            slot,
            config: identity_config_path(&config.root, 0, slot),
            listen: format!("127.0.0.1:{port}"),
        });
        specs.push(spec);
    }

    write_inventory(&config.root, &inventory)?;
    log::info!(
        "offline proxy pool ready: {} listener(s), inventory={}",
        specs.len(),
        config.root.join("inventory.json").display()
    );

    let mut shutdown = Box::pin(wait_for_shutdown());
    loop {
        tokio::select! {
            result = &mut shutdown => {
                result?;
                break;
            }
            () = tokio::time::sleep(Duration::from_secs(1)) => {
                for spec in &specs {
                    let key = SlotKey::from(spec);
                    if !supervisor.is_running(key)? {
                        let pid = supervisor
                            .start(spec)
                            .await
                            .with_context(|| format!(
                                "failed to restart offline proxy g{} s{}",
                                spec.group, spec.slot
                            ))?;
                        log::warn!(
                            "restarted offline proxy g{} s{} pid={pid}",
                            spec.group,
                            spec.slot
                        );
                    }
                }
            }
        }
    }

    supervisor.stop_all().await;
    Ok(())
}

fn write_inventory(root: &std::path::Path, inventory: &[InventoryEntry]) -> Result<()> {
    let path = root.join("inventory.json");
    let tmp = root.join("inventory.json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(inventory)?)?;
    fs::rename(&tmp, &path)
        .with_context(|| format!("failed to replace offline inventory {}", path.display()))
}
