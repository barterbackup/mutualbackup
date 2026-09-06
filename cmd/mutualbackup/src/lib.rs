use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use mb_core::Seed;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub format_version: u16,
    pub data_dir: PathBuf,
    pub seed_file: PathBuf,
    pub control_socket: PathBuf,
    pub failure_domain: String,
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
}

impl DaemonConfig {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != 1 {
            bail!("unsupported daemon config format version");
        }
        if self.failure_domain.is_empty() || self.failure_domain.len() > 256 {
            bail!("failure_domain must contain 1 to 256 bytes");
        }
        if self.parity_budget_bytes == 0 {
            bail!("parity_budget_bytes must be greater than zero");
        }
        if self.p2p_listen_addresses.is_empty() {
            bail!("at least one p2p listen address is required");
        }
        if self.data_dir == self.seed_file || self.control_socket == self.seed_file {
            bail!("daemon paths must be distinct");
        }
        Ok(())
    }
}

pub fn default_p2p_listen_addresses() -> Vec<String> {
    vec!["/ip4/0.0.0.0/udp/0/quic-v1".to_owned()]
}

pub fn read_config(path: &Path) -> Result<DaemonConfig> {
    let encoded = fs::read_to_string(path)
        .with_context(|| format!("cannot read daemon config {}", path.display()))?;
    let mut config: DaemonConfig = toml::from_str(&encoded)
        .with_context(|| format!("invalid daemon config {}", path.display()))?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.data_dir = resolve_config_path(base, &config.data_dir);
    config.seed_file = resolve_config_path(base, &config.seed_file);
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
    let encoded = fs::read_to_string(path)
        .with_context(|| format!("cannot read seed file {}", path.display()))?;
    Seed::from_str(encoded.trim()).context("invalid recovery seed file")
}

pub fn write_seed(path: &Path, seed: &Seed) -> Result<()> {
    write_new_private(
        path,
        format!("{}\n", seed.encode()).as_bytes(),
        "recovery seed",
    )?;
    let written = read_seed(path)?;
    if written.expose() != seed.expose() {
        bail!("installed recovery seed failed validation");
    }
    Ok(())
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
        let seed = Seed::from_bytes([44; 32]);
        write_seed(&temp.path().join("node.seed"), &seed).unwrap();
        write_config(
            &config_path,
            &DaemonConfig {
                format_version: 1,
                data_dir: PathBuf::from("state"),
                seed_file: PathBuf::from("node.seed"),
                control_socket: PathBuf::from("run/control.sock"),
                failure_domain: "disk-a".into(),
                parity_budget_bytes: 1024,
                p2p_listen_addresses: default_p2p_listen_addresses(),
                p2p_external_addresses: Vec::new(),
                p2p_bootstrap_addresses: Vec::new(),
                p2p_relay_addresses: Vec::new(),
                enable_relay_server: false,
            },
        )
        .unwrap();
        let loaded = read_config(&config_path).unwrap();
        assert_eq!(loaded.data_dir, temp.path().join("state"));
        assert_eq!(loaded.seed_file, temp.path().join("node.seed"));
        assert_eq!(loaded.control_socket, temp.path().join("run/control.sock"));
    }
}
