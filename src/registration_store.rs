use anyhow::{Context, Result};
use std::{
    fs::{self, File, OpenOptions},
    net::IpAddr,
    path::{Path, PathBuf},
};

use crate::{config::Config, register};

#[derive(Clone, Debug)]
pub struct RegistrationOptions {
    pub locale: String,
    pub model: String,
    pub device_name: Option<String>,
    pub jwt: Option<String>,
    pub reregister: bool,
}

#[derive(Clone, Debug)]
pub struct RegistrationStore {
    root: PathBuf,
}

impl RegistrationStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Return the MASQUE registration for `source_ip`, creating it on cache miss.
    ///
    /// Registrations are keyed by the selected outer source IP, not by transport:
    /// native CONNECT-IP and direct-L4 share the same enrolled MASQUE identity.
    ///
    /// # Errors
    /// Returns an error if the store cannot be locked/read/written or Cloudflare
    /// registration/enrollment fails.
    pub async fn resolve(
        &self,
        source_ip: Option<IpAddr>,
        options: &RegistrationOptions,
    ) -> Result<Config> {
        let entry_path = self.entry_path(source_ip);
        let lock_path = self.lock_path(source_ip);
        let root = self.root.clone();
        let lock = tokio::task::spawn_blocking(move || acquire_entry_lock(&root, &lock_path))
            .await
            .context("registration-store lock task failed")??;

        if !options.reregister
            && entry_path
                .try_exists()
                .with_context(|| format!("failed to inspect {}", entry_path.display()))?
        {
            match Config::load_async(&entry_path).await {
                Ok(config) => {
                    log::info!(
                        "Reusing WARP registration for {} from {}",
                        display_source(source_ip),
                        entry_path.display()
                    );
                    drop(lock);
                    return Ok(config);
                }
                Err(error) => {
                    log::warn!(
                        "Cached WARP registration for {} at {} is invalid; replacing it: {error:#}",
                        display_source(source_ip),
                        entry_path.display()
                    );
                }
            }
        }

        log::info!(
            "Creating WARP registration for {}{}",
            display_source(source_ip),
            if options.reregister {
                " (--reregister)"
            } else {
                ""
            }
        );
        let account = register::register(
            &options.model,
            &options.locale,
            options.jwt.as_deref(),
            source_ip,
        )
        .await?;
        let (private_key, public_key) = register::generate_ec_keypair()?;
        let enrolled = register::enroll_key(
            &account,
            &public_key,
            options.device_name.as_deref(),
            source_ip,
        )
        .await?;
        let config = Config::from_account_data(&enrolled, &account.token, &private_key)?;
        config.save_async(&entry_path).await?;
        log::info!(
            "Saved WARP registration for {} to {}",
            display_source(source_ip),
            entry_path.display()
        );
        drop(lock);
        Ok(config)
    }

    fn entry_path(&self, source_ip: Option<IpAddr>) -> PathBuf {
        self.root
            .join(format!("{}.json", registration_key(source_ip)))
    }

    fn lock_path(&self, source_ip: Option<IpAddr>) -> PathBuf {
        self.root
            .join(format!("{}.lock", registration_key(source_ip)))
    }
}

fn acquire_entry_lock(root: &Path, lock_path: &Path) -> Result<File> {
    fs::create_dir_all(root)
        .with_context(|| format!("failed to create registration store {}", root.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to secure registration store {}", root.display()))?;
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(lock_path)
        .with_context(|| format!("failed to open registration lock {}", lock_path.display()))?;
    fs2::FileExt::lock_exclusive(&file)
        .with_context(|| format!("failed to lock registration {}", lock_path.display()))?;
    Ok(file)
}

fn registration_key(source_ip: Option<IpAddr>) -> String {
    match source_ip {
        Some(IpAddr::V4(ip)) => format!("v4-{ip}"),
        Some(IpAddr::V6(ip)) => format!("v6-{}", ip.to_string().replace(':', "_")),
        None => "default-route".to_string(),
    }
}

fn display_source(source_ip: Option<IpAddr>) -> String {
    source_ip.map_or_else(|| "default route".to_string(), |ip| ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(token: &str) -> Config {
        Config {
            private_key: "key".to_string(),
            endpoint_v4: "192.0.2.1".to_string(),
            endpoint_v6: "2001:db8::1".to_string(),
            endpoint_pub_key: "public-key".to_string(),
            license: String::new(),
            id: "device-id".to_string(),
            access_token: token.to_string(),
            ipv4: "172.16.0.2".to_string(),
            ipv6: "2606:4700:110::2".to_string(),
        }
    }

    #[test]
    fn keys_are_stable_and_transport_agnostic() -> Result<()> {
        assert_eq!(registration_key(None), "default-route");
        assert_eq!(registration_key(Some("192.0.2.1".parse()?)), "v4-192.0.2.1");
        assert_eq!(
            registration_key(Some("2001:db8::1".parse()?)),
            "v6-2001_db8__1"
        );
        Ok(())
    }

    #[tokio::test]
    async fn existing_ip_registration_is_reused_without_network() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = RegistrationStore::new(dir.path());
        let source_ip = Some("2001:db8::1234".parse()?);
        config("cached-token").save(store.entry_path(source_ip))?;
        let options = RegistrationOptions {
            locale: "en_US".to_string(),
            model: "PC".to_string(),
            device_name: None,
            jwt: None,
            reregister: false,
        };

        let loaded = store.resolve(source_ip, &options).await?;
        assert_eq!(loaded.access_token, "cached-token");
        Ok(())
    }
}
