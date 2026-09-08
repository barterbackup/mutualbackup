use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mb_core::{NodeId, Seed};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_RECOVERY_FILE_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub format_version: u16,
    pub data_dir: PathBuf,
    #[serde(with = "node_id_text")]
    pub expected_node_id: NodeId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_file: Option<PathBuf>,
    pub control_socket: PathBuf,
    pub failure_domain: String,
    #[serde(default)]
    pub recovery_mode: bool,
    pub parity_budget_bytes: u64,
    #[serde(default = "default_p2p_listen_addresses")]
    pub p2p_listen_addresses: Vec<String>,
    #[serde(default)]
    pub p2p_external_addresses: Vec<String>,
    #[serde(default)]
    pub p2p_bootstrap_addresses: Vec<String>,
    #[serde(default)]
    pub p2p_relay_addresses: Vec<String>,
    #[serde(default)]
    pub enable_relay_server: bool,
    #[serde(default = "default_enable_hole_punching")]
    pub enable_hole_punching: bool,
    #[serde(default = "default_enable_dht_maintenance")]
    pub enable_dht_maintenance: bool,
}

impl DaemonConfig {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != 1 {
            bail!("unsupported daemon config format version");
        }
        if (!self.recovery_mode && self.failure_domain.is_empty())
            || self.failure_domain.len() > 256
        {
            bail!("failure_domain must contain 1 to 256 bytes");
        }
        if self.parity_budget_bytes == 0 {
            bail!("parity_budget_bytes must be greater than zero");
        }
        if self.p2p_listen_addresses.is_empty() && self.p2p_relay_addresses.is_empty() {
            bail!("at least one p2p listen or relay address is required");
        }
        if let Some(seed_file) = &self.seed_file
            && (self.data_dir == *seed_file || self.control_socket == *seed_file)
        {
            bail!("daemon paths must be distinct");
        }
        Ok(())
    }
}

pub fn default_p2p_listen_addresses() -> Vec<String> {
    vec!["/ip4/0.0.0.0/udp/0/quic-v1".to_owned()]
}

fn default_enable_hole_punching() -> bool {
    true
}

fn default_enable_dht_maintenance() -> bool {
    true
}

pub fn read_config(path: &Path) -> Result<DaemonConfig> {
    let encoded = fs::read_to_string(path)
        .with_context(|| format!("cannot read daemon config {}", path.display()))?;
    let mut config: DaemonConfig = toml::from_str(&encoded)
        .with_context(|| format!("invalid daemon config {}", path.display()))?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.data_dir = resolve_config_path(base, &config.data_dir);
    config.seed_file = config
        .seed_file
        .as_ref()
        .map(|path| resolve_config_path(base, path));
    config.control_socket = resolve_config_path(base, &config.control_socket);
    config.validate()?;
    Ok(config)
}

pub fn write_config(path: &Path, config: &DaemonConfig) -> Result<()> {
    config.validate()?;
    let encoded = toml::to_string_pretty(config)?;
    write_new_private(path, encoded.as_bytes(), "daemon config")
}

pub fn read_seed(path: &Path) -> Result<Seed> {
    let recovery = read_recovery_string(path)?;
    Seed::from_recovery_string(&recovery).context("invalid recovery string file")
}

pub fn read_recovery_string(path: &Path) -> Result<Zeroizing<String>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot securely open seed file {}", path.display()))?;
    validate_seed_file(&file, path)?;
    let mut bytes = Zeroizing::new(Vec::new());
    Read::by_ref(&mut file)
        .take((MAX_RECOVERY_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RECOVERY_FILE_BYTES {
        bail!("recovery string file exceeds size limit");
    }
    let text = std::str::from_utf8(&bytes).context("recovery string file is not valid UTF-8")?;
    Ok(Zeroizing::new(text.to_owned()))
}

pub fn write_seed(path: &Path, recovery_string: &str) -> Result<()> {
    let seed = Seed::from_recovery_string(recovery_string)
        .context("refusing to store an invalid recovery string")?;
    write_new_private(path, recovery_string.as_bytes(), "recovery string")?;
    let written = read_seed(path)?;
    if written.expose() != seed.expose() {
        bail!("installed recovery string failed validation");
    }
    Ok(())
}

fn validate_seed_file(file: &File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect seed file {}", path.display()))?;
    if !metadata.is_file() {
        bail!("recovery string path must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!("recovery string file must be owned by the current user");
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("recovery string file must not be accessible by group or others");
        }
    }
    Ok(())
}

mod node_id_text {
    use std::str::FromStr;

    use mb_core::NodeId;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &NodeId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<NodeId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        NodeId::from_str(&value).map_err(serde::de::Error::custom)
    }
}

fn write_new_private(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        bail!("{label} parent directory does not exist");
    }
    let temporary = parent.join(format!(".mutualbackup-{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("cannot create temporary {label} in {}", parent.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Err(error) = fs::hard_link(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        sync_directory(parent).ok();
        return Err(error).with_context(|| format!("cannot install {label} {}", path.display()));
    }
    fs::remove_file(&temporary)?;
    sync_directory(parent)?;
    Ok(())
}

fn resolve_config_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_paths_are_relative_to_the_config_file() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("node.toml");
        let recovery = "correct-horse-battery-staple-2026!";
        let seed = Seed::from_recovery_string(recovery).unwrap();
        write_seed(&temp.path().join("node.seed"), recovery).unwrap();
        write_config(
            &config_path,
            &DaemonConfig {
                format_version: 1,
                data_dir: PathBuf::from("state"),
                expected_node_id: mb_core::KeyMaterial::from_seed(&seed).node_id(),
                seed_file: Some(PathBuf::from("node.seed")),
                control_socket: PathBuf::from("run/control.sock"),
                failure_domain: "disk-a".into(),
                recovery_mode: false,
                parity_budget_bytes: 1024,
                p2p_listen_addresses: default_p2p_listen_addresses(),
                p2p_external_addresses: Vec::new(),
                p2p_bootstrap_addresses: Vec::new(),
                p2p_relay_addresses: Vec::new(),
                enable_relay_server: false,
                enable_hole_punching: true,
                enable_dht_maintenance: true,
            },
        )
        .unwrap();
        let loaded = read_config(&config_path).unwrap();
        assert_eq!(loaded.data_dir, temp.path().join("state"));
        assert_eq!(loaded.seed_file, Some(temp.path().join("node.seed")));
        assert_eq!(loaded.control_socket, temp.path().join("run/control.sock"));
    }

    #[cfg(unix)]
    #[test]
    fn recovery_file_rejects_public_permissions_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("recovery.txt");
        write_seed(&path, "correct-horse-battery-staple-2026!").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_seed(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let link = temp.path().join("recovery-link.txt");
        symlink(&path, &link).unwrap();
        assert!(read_seed(&link).is_err());
    }
}
