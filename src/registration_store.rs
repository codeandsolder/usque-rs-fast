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

    /// Return the selected MASQUE registration, creating it on cache miss.
    ///
    /// By default registrations are keyed by the selected outer source IP, not
    /// by transport: native CONNECT-IP and direct-L4 share the same enrolled
    /// MASQUE identity. `explicit_key` overrides only cache identity; registration
    /// and enrollment still bind to `source_ip`, so a stable identity can survive
    /// deliberate source-IP rotation.
    ///
    /// # Errors
    /// Returns an error if the store cannot be locked/read/written or Cloudflare
    /// registration/enrollment fails.
    pub async fn resolve(
        &self,
        source_ip: Option<IpAddr>,
        explicit_key: Option<&str>,
        options: &RegistrationOptions,
    ) -> Result<Config> {
        let key = registration_key(source_ip, explicit_key)?;
        let source = display_source(source_ip);
        let entry_path = self.entry_path(&key);
        let lock_path = self.lock_path(&key);
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
                        "Reusing WARP registration {key} for source {source} from {}",
                        entry_path.display()
                    );
                    drop(lock);
                    return Ok(config);
                }
                Err(error) => {
                    log::warn!(
                        "Cached WARP registration {key} for source {source} at {} is invalid; replacing it: {error:#}",
                        entry_path.display()
                    );
                }
            }
        }

        log::info!(
            "Creating WARP registration {key} through source {source}{}",
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
            "Saved WARP registration {key} created through source {source} to {}",
            entry_path.display()
        );
        drop(lock);
        Ok(config)
    }

    fn entry_path(&self, key: &str) -> PathBuf {
        self.root.join(format!("{key}.json"))
    }

    fn lock_path(&self, key: &str) -> PathBuf {
        self.root.join(format!("{key}.lock"))
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
    file.lock()
        .with_context(|| format!("failed to lock registration {}", lock_path.display()))?;
    Ok(file)
}

fn registration_key(source_ip: Option<IpAddr>, explicit_key: Option<&str>) -> Result<String> {
    if let Some(key) = explicit_key {
        anyhow::ensure!(
            !key.is_empty() && key.len() <= 128,
            "registration key must contain 1..=128 ASCII key characters"
        );
        anyhow::ensure!(
            key.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            "registration key may contain only ASCII letters, digits, '.', '_', and '-'"
        );
        return Ok(format!("named-{key}"));
    }
    Ok(match source_ip {
        Some(IpAddr::V4(ip)) => format!("v4-{ip}"),
        Some(IpAddr::V6(ip)) => format!("v6-{}", ip.to_string().replace(':', "_")),
        None => "default-route".to_string(),
    })
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
        assert_eq!(registration_key(None, None)?, "default-route");
        assert_eq!(
            registration_key(Some("192.0.2.1".parse()?), None)?,
            "v4-192.0.2.1"
        );
        assert_eq!(
            registration_key(Some("2001:db8::1".parse()?), None)?,
            "v6-2001_db8__1"
        );
        assert_eq!(
            registration_key(Some("2001:db8::1".parse()?), Some("pool-g0-s3"))?,
            "named-pool-g0-s3"
        );
        assert_eq!(
            registration_key(Some("2001:db8::2".parse()?), Some("pool-g0-s3"))?,
            "named-pool-g0-s3"
        );
        assert!(registration_key(None, Some("../escape")).is_err());
        assert!(registration_key(None, Some("")).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn existing_ip_registration_is_reused_without_network() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = RegistrationStore::new(dir.path());
        let source_ip = Some("2001:db8::1234".parse()?);
        let key = registration_key(source_ip, None)?;
        config("cached-token").save(store.entry_path(&key))?;
        let options = RegistrationOptions {
            locale: "en_US".to_string(),
            model: "PC".to_string(),
            device_name: None,
            jwt: None,
            reregister: false,
        };

        let loaded = store.resolve(source_ip, None, &options).await?;
        assert_eq!(loaded.access_token, "cached-token");
        Ok(())
    }

    #[tokio::test]
    async fn explicit_key_reuses_identity_across_source_rotation() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = RegistrationStore::new(dir.path());
        let key = registration_key(None, Some("pool-g0-s3"))?;
        config("stable-token").save(store.entry_path(&key))?;
        let options = RegistrationOptions {
            locale: "en_US".to_string(),
            model: "PC".to_string(),
            device_name: None,
            jwt: None,
            reregister: false,
        };

        let first = store
            .resolve(Some("2001:db8::1".parse()?), Some("pool-g0-s3"), &options)
            .await?;
        let rotated = store
            .resolve(Some("2001:db8::2".parse()?), Some("pool-g0-s3"), &options)
            .await?;
        assert_eq!(first.access_token, "stable-token");
        assert_eq!(rotated.access_token, "stable-token");
        Ok(())
    }
}
