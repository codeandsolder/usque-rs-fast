use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::register::AccountData;

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
    pub fn load(path: &str) -> Result<Self> {
        let path = Path::new(path);

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

    /// Persist the configuration, creating parent directories as needed.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or any filesystem operation fails.
    pub fn save(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        let path = Path::new(path);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options
            .open(path)
            .with_context(|| format!("failed to open config {}", path.display()))?;

        // OpenOptionsExt::mode only affects newly-created files. Tighten an existing config too.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .with_context(|| {
                    format!("failed to secure config permissions for {}", path.display())
                })?;
        }

        file.set_len(0)
            .with_context(|| format!("failed to truncate config {}", path.display()))?;
        file.write_all(json.as_bytes())
            .with_context(|| format!("failed to write config to {}", path.display()))
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
        let ep_v4 = peer.endpoint.v4.trim_end_matches(":0").to_string();
        let ep_v6 = peer.endpoint.v6.clone();
        let ep_v6 = ep_v6
            .trim_start_matches('[')
            .trim_end_matches("]:0")
            .trim_end_matches(":0")
            .to_string();

        Ok(Self {
            private_key: base64::engine::general_purpose::STANDARD.encode(priv_key_der),
            endpoint_v4: ep_v4,
            endpoint_v6: ep_v6,
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
    pub fn get_endpoint_pub_key_der(&self) -> Result<Vec<u8>> {
        use x509_cert::der::{DecodePem, Encode};

        let spki =
            x509_cert::spki::SubjectPublicKeyInfoOwned::from_pem(self.endpoint_pub_key.as_bytes())
                .context("failed to parse endpoint public key PEM")?;
        spki.to_der()
            .context("failed to encode endpoint public key as SPKI DER")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::register::{Account, Addresses, Endpoint, Interface, Peer, WarpConfig};

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
}
