use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProxyRecord {
    pub addr: String,
    pub group: usize,
    pub slot: usize,
    #[serde(default)]
    pub registered: bool,
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub v6: String,
    #[serde(default)]
    pub v4: String,
    #[serde(default)]
    pub pid: u32,
    #[serde(default, deserialize_with = "deserialize_unix_seconds")]
    pub last_keepalive: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PoolState {
    #[serde(default = "default_phase")]
    pub phase: String,
    #[serde(default)]
    pub v6_root: String,
    #[serde(default)]
    pub box_v6: String,
    #[serde(default)]
    pub box_v4: String,
    #[serde(default)]
    pub seen_v4: BTreeSet<String>,
    #[serde(default)]
    pub stale_count: usize,
    #[serde(default, deserialize_with = "deserialize_unix_seconds")]
    pub started_at: i64,
    #[serde(default)]
    pub proxies: Vec<ProxyRecord>,
}

fn default_phase() -> String {
    "init".to_string()
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StartedAt {
    Integer(i64),
    Float(f64),
}

fn deserialize_unix_seconds<'de, D>(deserializer: D) -> std::result::Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match StartedAt::deserialize(deserializer)? {
        StartedAt::Integer(value) => Ok(value),
        StartedAt::Float(value) => time::SignedDuration::checked_seconds_f64(value)
            .map(time::SignedDuration::whole_seconds)
            .ok_or_else(|| {
                serde::de::Error::custom(
                    "timestamp float must be finite and fit in i64 Unix seconds",
                )
            }),
    }
}

impl Default for PoolState {
    fn default() -> Self {
        Self {
            phase: default_phase(),
            v6_root: String::new(),
            box_v6: String::new(),
            box_v4: String::new(),
            seen_v4: BTreeSet::new(),
            stale_count: 0,
            started_at: time::OffsetDateTime::now_utc().unix_timestamp(),
            proxies: Vec::new(),
        }
    }
}

impl PoolState {
    /// Load persisted proxy-pool state.
    ///
    /// # Errors
    /// Returns an error when the state file cannot be read or decoded.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read pool state {}", path.display()))?;
        let mut state: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse pool state {}", path.display()))?;
        for proxy in &mut state.proxies {
            proxy.pid = 0;
        }
        if state.started_at == 0 {
            state.started_at = time::OffsetDateTime::now_utc().unix_timestamp();
        }
        Ok(state)
    }

    /// Atomically persist proxy-pool state.
    ///
    /// # Errors
    /// Returns an error if serialization, directory creation, file I/O, or rename fails.
    pub fn save(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("state path has no parent: {}", path.display()))?;
        fs::create_dir_all(parent)?;
        let tmp = temporary_sibling(path);
        let bytes = serde_json::to_vec_pretty(self)?;
        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("failed to create {}", tmp.display()))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path).with_context(|| format!("failed to replace {}", path.display()))
    }
}

/// Return the config path for one pool identity.
#[must_use]
pub fn identity_config_path(root: &Path, group: usize, slot: usize) -> PathBuf {
    root.join("identities")
        .join(format!("group-{group}"))
        .join(format!("slot-{slot}"))
        .join("config.json")
}

/// Return the suffix-list path for one remote prefix group.
#[must_use]
pub fn address_file(root: &Path, group: usize) -> PathBuf {
    root.join("addresses").join(format!("group-{group}.json"))
}

/// Load the stable per-group /128 suffix list.
///
/// # Errors
/// Returns an error when an existing suffix file cannot be read or decoded.
pub fn load_suffixes(root: &Path, group: usize) -> Result<Vec<String>> {
    let path = address_file(root, group);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

/// Atomically persist the stable per-group /128 suffix list.
///
/// # Errors
/// Returns an error for serialization, directory creation, file I/O, permission, or rename failures.
pub fn save_suffixes(root: &Path, group: usize, suffixes: &[String]) -> Result<()> {
    let path = address_file(root, group);
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("address path has no parent"))?;
    fs::create_dir_all(parent)?;
    let tmp = temporary_sibling(&path);
    fs::write(&tmp, serde_json::to_vec_pretty(suffixes)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn temporary_sibling(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(|| "state".into(), std::ffi::OsStr::to_os_string);
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_state_round_trip_resets_process_ids() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.json");
        let mut state = PoolState {
            started_at: 123,
            ..PoolState::default()
        };
        state.phase = "locked".to_string();
        state.proxies.push(ProxyRecord {
            addr: "2001:db8::1:2".to_string(),
            group: 0,
            slot: 3,
            registered: true,
            locked: true,
            v6: "2001:db8::1:2".to_string(),
            v4: "104.16.1.2".to_string(),
            pid: 4242,
            last_keepalive: 123,
        });
        state.save(&path)?;

        let loaded = PoolState::load(&path)?;
        assert_eq!(loaded.phase, "locked");
        assert_eq!(loaded.started_at, 123);
        assert_eq!(loaded.proxies.len(), 1);
        assert_eq!(loaded.proxies[0].last_keepalive, 123);
        assert_eq!(loaded.proxies[0].pid, 0);
        assert!(loaded.proxies[0].locked);
        Ok(())
    }

    #[test]
    fn loads_legacy_float_timestamps_and_ignores_unknown_fields() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.json");
        fs::write(
            &path,
            br#"{
                "phase": "locked",
                "started_at": 123.75,
                "port": 20000,
                "proxies": [{
                    "addr": "2001:db8::1:2",
                    "group": 0,
                    "slot": 3,
                    "registered": true,
                    "locked": true,
                    "v6": "2001:db8::1:2",
                    "v4": "104.16.1.2",
                    "pid": 4242,
                    "last_keepalive": 123.875
                }]
            }"#,
        )?;

        let loaded = PoolState::load(&path)?;
        assert_eq!(loaded.started_at, 123);
        assert_eq!(loaded.proxies[0].last_keepalive, 123);
        assert_eq!(loaded.phase, "locked");
        assert_eq!(loaded.proxies.len(), 1);
        assert!(loaded.proxies[0].locked);
        assert_eq!(loaded.proxies[0].pid, 0);
        Ok(())
    }

    #[test]
    fn identity_layout_is_stable() {
        assert_eq!(
            identity_config_path(Path::new("/var/lib/usque-pool"), 2, 7),
            PathBuf::from("/var/lib/usque-pool/identities/group-2/slot-7/config.json")
        );
    }
}
