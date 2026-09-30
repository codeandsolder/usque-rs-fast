use crate::{config::Config, register};
use anyhow::{Context, Result};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::process::{Child, Command};

use super::state::identity_config_path;

#[derive(Clone, Debug)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct ChildTransport {
    pub connect_port: u16,
    pub sni: String,
    pub keepalive_period: Duration,
    pub mtu: u32,
    pub no_tunnel_ipv4: bool,
    pub no_tunnel_ipv6: bool,
    pub use_ipv6_endpoint: bool,
}

impl Default for ChildTransport {
    fn default() -> Self {
        Self {
            connect_port: 443,
            sni: "consumer-masque.cloudflareclient.com".to_string(),
            keepalive_period: Duration::from_secs(30),
            mtu: 1280,
            no_tunnel_ipv4: false,
            no_tunnel_ipv6: false,
            use_ipv6_endpoint: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChildSpec {
    pub group: usize,
    pub slot: usize,
    pub bind_ip: IpAddr,
    pub source_ip: Option<IpAddr>,
    pub port: u16,
    pub auth: Option<ProxyAuth>,
    pub transport: ChildTransport,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SlotKey {
    pub group: usize,
    pub slot: usize,
}

impl From<&ChildSpec> for SlotKey {
    fn from(value: &ChildSpec) -> Self {
        Self {
            group: value.group,
            slot: value.slot,
        }
    }
}

pub struct Supervisor {
    executable: PathBuf,
    root: PathBuf,
    children: BTreeMap<SlotKey, Child>,
}

impl Supervisor {
    /// Create a child-process supervisor for proxy identities.
    ///
    /// # Errors
    /// Returns an error if the current executable path cannot be resolved.
    pub fn new(root: PathBuf) -> Result<Self> {
        Ok(Self {
            executable: std::env::current_exe().context("failed to resolve current executable")?,
            root,
            children: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn config_path(&self, group: usize, slot: usize) -> PathBuf {
        identity_config_path(&self.root, group, slot)
    }

    /// Ensure the WARP identity for one slot exists.
    ///
    /// # Errors
    /// Returns an error if registration, key enrollment, or config persistence fails.
    pub async fn ensure_identity(&self, group: usize, slot: usize) -> Result<bool> {
        let path = self.config_path(group, slot);
        if path.exists() {
            Config::load(path_to_str(&path)?)?;
            return Ok(false);
        }

        let identities_dir = self.root.join("identities");
        let group_dir = identities_dir.join(format!("group-{group}"));
        let slot_dir = group_dir.join(format!("slot-{slot}"));
        create_identity_dir(&identities_dir)?;
        create_identity_dir(&group_dir)?;
        create_identity_dir(&slot_dir)?;

        let name = format!("g{group}-s{slot}");
        log::info!("registering WARP identity {name}");
        let account = register::register("PC", "en_US", None).await?;
        let (private_key, public_key) = register::generate_ec_keypair()?;
        let enrolled = register::enroll_key(&account, &public_key, Some(&name)).await?;
        let config = Config::from_account_data(&enrolled, &account.token, &private_key)?;
        config.save(path_to_str(&path)?)?;
        Ok(true)
    }

    /// Start or replace one proxy child.
    ///
    /// # Errors
    /// Returns an error if the existing child cannot be stopped or the new
    /// process cannot be spawned.
    pub async fn start(&mut self, spec: &ChildSpec) -> Result<u32> {
        let key = SlotKey::from(spec);
        self.stop(key).await?;

        let config = self.config_path(spec.group, spec.slot);
        let mut command = Command::new(&self.executable);
        command
            .arg("-c")
            .arg(&config)
            .arg("socks")
            .arg("--bind")
            .arg(spec.bind_ip.to_string())
            .arg("--port")
            .arg(spec.port.to_string())
            .arg("--connect-port")
            .arg(spec.transport.connect_port.to_string())
            .arg("--sni-address")
            .arg(&spec.transport.sni)
            .arg("--keepalive-period")
            .arg(spec.transport.keepalive_period.as_secs().to_string())
            .arg("--mtu")
            .arg(spec.transport.mtu.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);

        if spec.transport.use_ipv6_endpoint {
            command.arg("--ipv6");
        }
        if spec.transport.no_tunnel_ipv4 {
            command.arg("--no-tunnel-ipv4");
        }
        if spec.transport.no_tunnel_ipv6 {
            command.arg("--no-tunnel-ipv6");
        }
        if let Some(source_ip) = spec.source_ip {
            command.arg("--source-ip").arg(source_ip.to_string());
        }
        if let Some(auth) = &spec.auth {
            command
                .arg("--username")
                .arg(&auth.username)
                .arg("--password")
                .arg(&auth.password);
        }

        let child = command.spawn().with_context(|| {
            format!(
                "failed to start proxy child for g{} s{}",
                spec.group, spec.slot
            )
        })?;
        let pid = child
            .id()
            .ok_or_else(|| anyhow::anyhow!("spawned proxy child has no process id"))?;
        self.children.insert(key, child);
        Ok(pid)
    }

    /// Check whether a child is still running.
    ///
    /// # Errors
    /// Returns an error if querying child state fails.
    pub fn is_running(&mut self, key: SlotKey) -> Result<bool> {
        let Some(child) = self.children.get_mut(&key) else {
            return Ok(false);
        };
        match child.try_wait()? {
            None => Ok(true),
            Some(status) => {
                log::warn!(
                    "proxy child g{} s{} exited with {status}",
                    key.group,
                    key.slot
                );
                self.children.remove(&key);
                Ok(false)
            }
        }
    }

    /// Stop one managed child if present.
    ///
    /// # Errors
    /// Returns an error if the child cannot be killed or reaped.
    pub async fn stop(&mut self, key: SlotKey) -> Result<()> {
        let Some(mut child) = self.children.remove(&key) else {
            return Ok(());
        };
        if child.try_wait()?.is_none() {
            child.kill().await?;
        }
        let _status = child.wait().await?;
        Ok(())
    }

    pub async fn stop_all(&mut self) {
        let keys: Vec<_> = self.children.keys().copied().collect();
        for key in keys {
            if let Err(error) = self.stop(key).await {
                log::warn!(
                    "failed to stop proxy child g{} s{}: {error:#}",
                    key.group,
                    key.slot
                );
            }
        }
    }
}

/// Derive the deterministic listener port for a pool slot.
///
/// # Errors
/// Returns an error for a zero stride, a slot outside its group's stride,
/// arithmetic overflow, or a derived port above 65535.
pub fn port_for(base: u16, stride: u16, group: usize, slot: usize) -> Result<u16> {
    if stride == 0 {
        anyhow::bail!("proxy port stride must be greater than zero");
    }
    if slot >= usize::from(stride) {
        anyhow::bail!("proxy slot {slot} exceeds stride {stride}; listener ranges would overlap");
    }
    let value = usize::from(base)
        .checked_add(
            group
                .checked_mul(usize::from(stride))
                .ok_or_else(|| anyhow::anyhow!("proxy port group overflow"))?,
        )
        .and_then(|value| value.checked_add(slot))
        .ok_or_else(|| anyhow::anyhow!("proxy port overflow"))?;
    u16::try_from(value).context("derived proxy port exceeds 65535")
}

/// Wait for the process shutdown signal used by pool supervisors.
///
/// # Errors
/// Returns an error if the platform signal handler cannot be installed or awaited.
pub async fn wait_for_shutdown() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("failed to listen for Ctrl-C")?,
            _ = terminate.recv() => {}
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("failed to listen for Ctrl-C")
    }
}

fn create_identity_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("failed to create identity directory {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "failed to restore traversable permissions on {}",
                    path.display()
                )
            },
        )?;
    }
    Ok(())
}

fn path_to_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("path is not valid UTF-8: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_layout_matches_warpproxy() -> Result<()> {
        assert_eq!(port_for(20_000, 1_000, 0, 0)?, 20_000);
        assert_eq!(port_for(20_000, 1_000, 2, 7)?, 22_007);
        assert!(port_for(65_000, 1_000, 1, 0).is_err());
        assert!(port_for(20_000, 1_000, 0, 1_000).is_err());
        assert!(port_for(20_000, 0, 0, 0).is_err());
        Ok(())
    }
}
