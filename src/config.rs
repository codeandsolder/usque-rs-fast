use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;
#[cfg(not(windows))]
use std::{
    fs::{File, OpenOptions},
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::account::AccountData;

#[cfg(not(windows))]
static TEMP_CONFIG_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(not(windows))]
struct TempConfigGuard {
    path: PathBuf,
    committed: bool,
}

#[cfg(not(windows))]
impl TempConfigGuard {
    fn commit(mut self, target: &Path) -> io::Result<()> {
        fs::rename(&self.path, target)?;
        self.committed = true;
        Ok(())
    }
}

#[cfg(not(windows))]
impl Drop for TempConfigGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(not(windows))]
fn create_config_temp(parent: &Path) -> io::Result<(File, TempConfigGuard)> {
    for _ in 0..64 {
        let sequence = TEMP_CONFIG_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(".usque-config-{}-{sequence}", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&path) {
            Ok(file) => {
                return Ok((
                    file,
                    TempConfigGuard {
                        path,
                        committed: false,
                    },
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique temporary config file",
    ))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub private_key: String,
    pub endpoint_v4: String,
    pub endpoint_v6: String,
    pub endpoint_pub_key: String,
    #[serde(default)]
    pub license: String,
    pub id: String,
    pub access_token: String,
    pub ipv4: String,
    pub ipv6: String,
}

impl Config {
    /// Load and parse a saved WARP configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be inspected/read, its permissions
    /// cannot be tightened on Unix, or the JSON is invalid.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let metadata = fs::metadata(path)
                .with_context(|| format!("failed to inspect config {}", path.display()))?;
            if metadata.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(
                    || format!("failed to secure config permissions for {}", path.display()),
                )?;
            }
        }

        let data = fs::read_to_string(path)
            .with_context(|| format!("failed to read config from {}", path.display()))?;
        serde_json::from_str(&data).with_context(|| "failed to parse config JSON")
    }

    /// Load a saved WARP configuration without blocking an async runtime worker.
    ///
    /// # Errors
    ///
    /// Returns an error if the blocking task cannot be joined or configuration loading fails.
    pub async fn load_async(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        tokio::task::spawn_blocking(move || Self::load(path))
            .await
            .context("config load task failed")?
    }

    /// Persist the configuration, creating parent directories as needed.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or any filesystem operation fails.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;

        #[cfg(not(windows))]
        {
            let (mut file, temp) = create_config_temp(parent).with_context(|| {
                format!("failed to create temporary config in {}", parent.display())
            })?;

            file.write_all(json.as_bytes())
                .with_context(|| format!("failed to write config for {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("failed to sync config for {}", path.display()))?;
            drop(file);

            temp.commit(path).with_context(|| {
                format!("failed to atomically replace config {}", path.display())
            })?;
        }

        #[cfg(windows)]
        {
            let mut file = tempfile::Builder::new()
                .prefix(".usque-config-")
                .tempfile_in(parent)
                .with_context(|| {
                    format!("failed to create temporary config in {}", parent.display())
                })?;
            file.write_all(json.as_bytes())
                .with_context(|| format!("failed to write config for {}", path.display()))?;
            file.as_file()
                .sync_all()
                .with_context(|| format!("failed to sync config for {}", path.display()))?;
            file.persist(path)
                .map_err(|error| error.error)
                .with_context(|| {
                    format!("failed to atomically replace config {}", path.display())
                })?;
        }

        #[cfg(unix)]
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("failed to sync config directory {}", parent.display()))?;

        Ok(())
    }

    /// Persist the configuration without blocking an async runtime worker.
    ///
    /// # Errors
    ///
    /// Returns an error if the blocking task cannot be joined or persistence fails.
    pub async fn save_async(&self, path: impl AsRef<Path>) -> Result<()> {
        let config = self.clone();
        let path = path.as_ref().to_path_buf();
        tokio::task::spawn_blocking(move || config.save(path))
            .await
            .context("config save task failed")?
    }

    /// Build a local configuration from a successful registration response.
    ///
    /// # Errors
    ///
    /// Returns an error when the response contains no usable WARP peer.
    pub fn from_account_data(
        account: &AccountData,
        token: &str,
        priv_key_der: &[u8],
    ) -> Result<Self> {
        let peer = account
            .config
            .peers
            .first()
            .context("registration response contained no WARP peers")?;
        let ep_v4 = parse_endpoint_ip(&peer.endpoint.v4)
            .with_context(|| format!("invalid IPv4 WARP endpoint {:?}", peer.endpoint.v4))?;
        anyhow::ensure!(
            ep_v4.is_ipv4(),
            "IPv4 WARP endpoint resolved to an IPv6 address: {ep_v4}"
        );
        let ep_v6 = parse_endpoint_ip(&peer.endpoint.v6)
            .with_context(|| format!("invalid IPv6 WARP endpoint {:?}", peer.endpoint.v6))?;
        anyhow::ensure!(
            ep_v6.is_ipv6(),
            "IPv6 WARP endpoint resolved to an IPv4 address: {ep_v6}"
        );

        Ok(Self {
            private_key: base64::engine::general_purpose::STANDARD.encode(priv_key_der),
            endpoint_v4: ep_v4.to_string(),
            endpoint_v6: ep_v6.to_string(),
            endpoint_pub_key: peer.public_key.clone(),
            license: account.account.license.clone().unwrap_or_default(),
            id: account.id.clone(),
            access_token: token.to_string(),
            ipv4: account.config.interface.addresses.v4.clone(),
            ipv6: account.config.interface.addresses.v6.clone(),
        })
    }

    /// Decode the stored EC private key.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured key is not valid base64.
    pub fn get_ec_private_key_der(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.private_key)
            .with_context(|| "failed to decode private key from base64")
    }

    /// Decode the pinned endpoint public key to SPKI DER.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured PEM is invalid or cannot be encoded.
    #[cfg(any(
        feature = "tun",
        feature = "http-proxy",
        feature = "https-proxy",
        feature = "socks5-proxy"
    ))]
    pub fn get_endpoint_pub_key_der(&self) -> Result<Vec<u8>> {
        let key = boring::pkey::PKey::public_key_from_pem(self.endpoint_pub_key.as_bytes())
            .context("failed to parse endpoint public key PEM")?;
        key.public_key_to_der()
            .context("failed to encode endpoint public key as SPKI DER")
    }
}

fn parse_endpoint_ip(endpoint: &str) -> Result<std::net::IpAddr> {
    if let Ok(ip) = endpoint.parse::<std::net::IpAddr>() {
        return Ok(ip);
    }
    endpoint
        .parse::<std::net::SocketAddr>()
        .map(|address| address.ip())
        .with_context(|| {
            format!("endpoint is not an IP address or IP socket address: {endpoint:?}")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{Account, Addresses, Endpoint, Interface, Peer, WarpConfig};

    fn account_data(peers: Vec<Peer>) -> AccountData {
        AccountData {
            id: "device-id".to_string(),
            token: "registration-token".to_string(),
            account: Account { license: None },
            config: WarpConfig {
                peers,
                interface: Interface {
                    addresses: Addresses {
                        v4: "172.16.0.2".to_string(),
                        v6: "2606:4700:110::2".to_string(),
                    },
                },
            },
        }
    }

    #[test]
    fn legacy_go_config_without_license_is_accepted() -> Result<()> {
        let json = r#"{
            "private_key": "key",
            "endpoint_v4": "192.0.2.1",
            "endpoint_v6": "2001:db8::1",
            "endpoint_h2_v4": "192.0.2.1",
            "endpoint_h2_v6": "",
            "endpoint_pub_key": "public-key",
            "id": "device-id",
            "access_token": "token",
            "ipv4": "172.16.0.2",
            "ipv6": "2606:4700:110::2"
        }"#;

        let cfg: Config = serde_json::from_str(json)?;
        assert_eq!(cfg.license, "");
        assert_eq!(cfg.endpoint_v4, "192.0.2.1");
        Ok(())
    }

    #[test]
    fn from_account_data_rejects_missing_peer() {
        let result = Config::from_account_data(&account_data(Vec::new()), "token", b"key");
        assert!(result.is_err(), "missing peer must be rejected");
        let Err(error) = result else {
            return;
        };
        assert!(
            error.to_string().contains("no WARP peers"),
            "unexpected error: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_uses_owner_only_permissions() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.json");
        let cfg = Config {
            private_key: "secret-key".to_string(),
            endpoint_v4: "192.0.2.1".to_string(),
            endpoint_v6: "2001:db8::1".to_string(),
            endpoint_pub_key: "public-key".to_string(),
            license: String::new(),
            id: "id".to_string(),
            access_token: "secret-token".to_string(),
            ipv4: "172.16.0.2".to_string(),
            ipv6: "2606:4700:110::2".to_string(),
        };

        let path_string = path.to_string_lossy().into_owned();
        cfg.save(&path_string)?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        cfg.save(&path_string)?;
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    #[test]
    fn save_replaces_existing_config_without_leaving_a_temporary_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.json");
        let mut cfg = Config {
            private_key: "secret-key".to_string(),
            endpoint_v4: "192.0.2.1".to_string(),
            endpoint_v6: "2001:db8::1".to_string(),
            endpoint_pub_key: "public-key".to_string(),
            license: String::new(),
            id: "id".to_string(),
            access_token: "first-token".to_string(),
            ipv4: "172.16.0.2".to_string(),
            ipv6: "2606:4700:110::2".to_string(),
        };

        cfg.save(&path)?;
        cfg.access_token = "second-token".to_string();
        cfg.save(&path)?;

        let loaded = Config::load(&path)?;
        assert_eq!(loaded.access_token, "second-token");
        assert!(!path.with_file_name("config.json.tmp").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn save_ignores_preexisting_fixed_temp_symlink() -> Result<()> {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.json");
        let victim = dir.path().join("victim");
        fs::write(&victim, b"leave-me-alone")?;
        symlink(&victim, dir.path().join("config.json.tmp"))?;

        let cfg = Config {
            private_key: "secret-key".to_string(),
            endpoint_v4: "192.0.2.1".to_string(),
            endpoint_v6: "2001:db8::1".to_string(),
            endpoint_pub_key: "public-key".to_string(),
            license: String::new(),
            id: "id".to_string(),
            access_token: "secret-token".to_string(),
            ipv4: "172.16.0.2".to_string(),
            ipv6: "2606:4700:110::2".to_string(),
        };

        cfg.save(&path)?;
        assert_eq!(fs::read(&victim)?, b"leave-me-alone");
        assert_eq!(Config::load(&path)?.access_token, "secret-token");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn load_repairs_permissive_permissions() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.json");
        let cfg = Config {
            private_key: "secret-key".to_string(),
            endpoint_v4: "192.0.2.1".to_string(),
            endpoint_v6: "2001:db8::1".to_string(),
            endpoint_pub_key: "public-key".to_string(),
            license: String::new(),
            id: "id".to_string(),
            access_token: "secret-token".to_string(),
            ipv4: "172.16.0.2".to_string(),
            ipv6: "2606:4700:110::2".to_string(),
        };
        fs::write(&path, serde_json::to_vec(&cfg)?)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;

        let path_string = path.to_string_lossy().into_owned();
        Config::load(&path_string)?;
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    #[test]
    fn from_account_data_accepts_peer() -> Result<()> {
        let peer = Peer {
            public_key: "public-key".to_string(),
            endpoint: Endpoint {
                v4: "192.0.2.1:0".to_string(),
                v6: "[2001:db8::1]:0".to_string(),
            },
        };
        let cfg = Config::from_account_data(&account_data(vec![peer]), "token", b"key")?;
        assert_eq!(cfg.endpoint_v4, "192.0.2.1");
        assert_eq!(cfg.endpoint_v6, "2001:db8::1");
        Ok(())
    }

    #[test]
    fn endpoint_parser_does_not_strip_ipv6_hextets_that_end_in_zero() -> Result<()> {
        assert_eq!(parse_endpoint_ip("2001:db8::0")?.to_string(), "2001:db8::");
        assert_eq!(
            parse_endpoint_ip("[2001:db8::10]:0")?.to_string(),
            "2001:db8::10"
        );
        Ok(())
    }

    #[test]
    fn malformed_endpoint_is_rejected_during_registration_conversion() {
        let peer = Peer {
            public_key: "public-key".to_string(),
            endpoint: Endpoint {
                v4: "not-an-ip:0".to_string(),
                v6: "[2001:db8::1]:0".to_string(),
            },
        };
        assert!(Config::from_account_data(&account_data(vec![peer]), "token", b"key").is_err());
    }
}
