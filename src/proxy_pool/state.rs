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
    #[serde(default)]
    pub last_keepalive: f64,
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
    #[serde(default)]
    pub started_at: f64,
    #[serde(default)]
    pub proxies: Vec<ProxyRecord>,
}

fn default_phase() -> String {
    "init".to_string()
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
            started_at: time::OffsetDateTime::now_utc().unix_timestamp() as f64,
            proxies: Vec::new(),
        }
    }
}

impl PoolState {
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
            state.started_at = time::OffsetDateTime::now_utc().unix_timestamp() as f64;
        }
        Ok(state)
    }

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

pub fn identity_config_path(root: &Path, group: usize, slot: usize) -> PathBuf {
    root.join("identities")
        .join(format!("group-{group}"))
        .join(format!("slot-{slot}"))
        .join("config.json")
}

pub fn address_file(root: &Path, group: usize) -> PathBuf {
    root.join("addresses").join(format!("group-{group}.json"))
}

pub fn load_suffixes(root: &Path, group: usize) -> Result<Vec<String>> {
    let path = address_file(root, group);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

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
    fn old_warp_pool_proxy_state_is_accepted() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.json");
        fs::write(
            &path,
            br#"{
              "phase":"locked",
              "started_at":123.5,
              "seen_v4":["104.16.1.2"],
              "proxies":[{
                "addr":"2001:db8::1:2",
                "group":0,
                "slot":3,
                "registered":true,
                "locked":true,
                "v6":"2001:db8::1:2",
                "v4":"104.16.1.2",
                "pid":4242,
                "last_keepalive":123.0,
                "port":20003
              }]
            }"#,
        )?;
        let state = PoolState::load(&path)?;
        assert_eq!(state.phase, "locked");
        assert_eq!(state.proxies.len(), 1);
        assert_eq!(state.started_at, 123.5);
        assert_eq!(state.proxies[0].pid, 0);
        assert!(state.proxies[0].locked);
        Ok(())
    }

    #[test]
    fn identity_layout_matches_legacy_pool() {
        assert_eq!(
            identity_config_path(Path::new("/opt/warp-pool"), 2, 7),
            PathBuf::from("/opt/warp-pool/identities/group-2/slot-7/config.json")
        );
    }
}
