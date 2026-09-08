use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use conf::Conf;
use mb_core::{NodeId, Seed};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const IDENTITY_MANIFEST_FILE: &str = "identity.toml";
const MAX_IDENTITY_MANIFEST_BYTES: usize = 16 * 1024;
const MAX_RECOVERY_FILE_BYTES: usize = 16 * 1024;
const DEFAULT_PARITY_BUDGET_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const DEFAULT_MAX_CONNECTIONS: usize = 32;

/// Human-owned daemon options, populated from flags over an optional TOML file.
#[derive(Clone, Debug, Eq, PartialEq, Conf, Serialize)]
#[conf(name = "mutualbackupd", version, serde, test)]
pub struct DaemonOptions {
    /// Optional TOML configuration file. Command-line values override it.
    #[conf(parameter, long = "config", serde(skip))]
    #[serde(skip)]
    pub config_file: Option<PathBuf>,

    /// Private local state directory containing the application identity manifest.
    #[conf(parameter, long)]
    pub data_dir: PathBuf,

    /// Optional private recovery-string file for unattended automatic unlock.
    #[conf(parameter, long)]
    pub seed_file: Option<PathBuf>,

    /// Unix socket used by the local CLI.
    #[conf(
        parameter,
        long,
        default(default_control_socket()),
        default_help_str = "below XDG_RUNTIME_DIR"
    )]
    pub control_socket: PathBuf,

    /// Human correlation label for a new node's disk, host, site, or operator.
    #[conf(parameter, long)]
    pub failure_domain: Option<String>,

    /// Maximum number of locally stored parity bytes.
    #[conf(parameter, long, default(DEFAULT_PARITY_BUDGET_BYTES))]
    pub parity_budget_bytes: u64,

    /// QUIC listen multiaddress; repeat for multiple listeners.
    #[conf(repeat, long = "listen", serde(rename = "p2p_listen_addresses"))]
    pub p2p_listen_addresses: Vec<String>,

    /// Public QUIC multiaddress; repeat for multiple advertised addresses.
    #[conf(
        repeat,
        long = "external-address",
        serde(rename = "p2p_external_addresses")
    )]
    pub p2p_external_addresses: Vec<String>,

    /// Bootstrap multiaddress ending in /p2p/PEER_ID; repeat as needed.
    #[conf(repeat, long = "bootstrap", serde(rename = "p2p_bootstrap_addresses"))]
    pub p2p_bootstrap_addresses: Vec<String>,

    /// Relay multiaddress ending in /p2p/PEER_ID; repeat as needed.
    #[conf(repeat, long = "relay", serde(rename = "p2p_relay_addresses"))]
    pub p2p_relay_addresses: Vec<String>,

    /// Whether this daemon accepts bounded relay reservations and circuits.
    #[conf(parameter, long, default(false))]
    pub enable_relay_server: bool,

    /// Whether relay connections may be upgraded through DCUtR.
    #[conf(parameter, long, default(true))]
    pub enable_hole_punching: bool,

    /// Whether this daemon bootstraps, publishes, and refreshes DHT records.
    #[conf(parameter, long, default(true))]
    pub enable_dht_maintenance: bool,

    /// Bound for established libp2p sessions and concurrent peer workers.
    #[conf(parameter, long, default(DEFAULT_MAX_CONNECTIONS))]
    pub max_connections: usize,
}

impl DaemonOptions {
    pub fn validate(&self, identity: &IdentityManifest) -> Result<()> {
        if identity.intent == InitializationIntent::New
            && self.failure_domain.as_deref().is_none_or(str::is_empty)
        {
            bail!("failure_domain must be set for a newly initialized node");
        }
        if self
            .failure_domain
            .as_ref()
            .is_some_and(|domain| domain.is_empty() || domain.len() > 256)
        {
            bail!("failure_domain must contain 1 to 256 bytes when set");
        }
        if self.parity_budget_bytes == 0 {
            bail!("parity_budget_bytes must be greater than zero");
        }
        if self.p2p_listen_addresses.is_empty() && self.p2p_relay_addresses.is_empty() {
            bail!("at least one --listen or --relay address is required");
        }
        if self.max_connections == 0 {
            bail!("max_connections must be greater than zero");
        }
        if let Some(seed_file) = &self.seed_file
            && (self.data_dir == *seed_file || self.control_socket == *seed_file)
        {
            bail!("daemon paths must be distinct");
        }
        Ok(())
    }

    pub fn effective_failure_domain(&self, identity: &IdentityManifest) -> String {
        match identity.intent {
            InitializationIntent::New => self.failure_domain.clone().unwrap_or_default(),
            InitializationIntent::Recovery => String::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InitializationIntent {
    New,
    Recovery,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityManifest {
    pub format_version: u16,
    #[serde(with = "node_id_text")]
    pub expected_node_id: NodeId,
    pub intent: InitializationIntent,
}

impl IdentityManifest {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != 1 {
            bail!("unsupported identity manifest format version");
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum DaemonOptionsError {
    #[error("cannot load daemon configuration: {0:#}")]
    Load(#[source] anyhow::Error),
    #[error(transparent)]
    Parse(#[from] conf::Error),
}

pub fn read_daemon_options(
    args: impl IntoIterator<Item = impl Into<OsString>>,
) -> std::result::Result<DaemonOptions, DaemonOptionsError> {
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let config_path = conf::find_parameter("config", args.iter().cloned()).map(PathBuf::from);
    let builder = DaemonOptions::conf_builder()
        .args(args)
        .env(std::iter::empty::<(OsString, OsString)>());
    match config_path {
        Some(path) => {
            let canonical_path = path.canonicalize().map_err(|error| {
                DaemonOptionsError::Load(
                    anyhow::Error::new(error)
                        .context(format!("cannot resolve daemon config {}", path.display())),
                )
            })?;
            let encoded = fs::read_to_string(&canonical_path).map_err(|error| {
                DaemonOptionsError::Load(anyhow::Error::new(error).context(format!(
                    "cannot read daemon config {}",
                    canonical_path.display()
                )))
            })?;
            let mut document: toml::Value = toml::from_str(&encoded).map_err(|error| {
                DaemonOptionsError::Load(anyhow::Error::new(error).context(format!(
                    "invalid daemon config {}",
                    canonical_path.display()
                )))
            })?;
            resolve_document_paths(
                &mut document,
                canonical_path.parent().unwrap_or_else(|| Path::new(".")),
            )
            .map_err(DaemonOptionsError::Load)?;
            builder
                .doc(canonical_path.display().to_string(), document)
                .try_parse()
                .map_err(DaemonOptionsError::Parse)
        }
        None => builder.try_parse().map_err(DaemonOptionsError::Parse),
    }
}

pub fn default_control_socket() -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime).join("mutualbackup/control.sock")
    } else {
        std::env::temp_dir()
            .join(format!("mutualbackup-{}", unsafe { libc::geteuid() }))
            .join("control.sock")
    }
}

pub fn identity_manifest_path(data_dir: &Path) -> PathBuf {
    data_dir.join(IDENTITY_MANIFEST_FILE)
}

pub fn initialize_identity(
    data_dir: &Path,
    seed: &Seed,
    intent: InitializationIntent,
) -> Result<IdentityManifest> {
    ensure_empty_private_data_dir(data_dir)?;
    let manifest = IdentityManifest {
        format_version: 1,
        expected_node_id: mb_core::KeyMaterial::from_seed(seed).node_id(),
        intent,
    };
    manifest.validate()?;
    let encoded = toml::to_string_pretty(&manifest)?;
    write_new_private(
        &identity_manifest_path(data_dir),
        encoded.as_bytes(),
        "identity manifest",
    )?;
    Ok(manifest)
}

pub fn read_identity_manifest(data_dir: &Path) -> Result<IdentityManifest> {
    let path = identity_manifest_path(data_dir);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("cannot open identity manifest {}", path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("identity manifest must be a regular file");
    }
    let mut encoded = String::new();
    Read::by_ref(&mut file)
        .take((MAX_IDENTITY_MANIFEST_BYTES + 1) as u64)
        .read_to_string(&mut encoded)?;
    if encoded.len() > MAX_IDENTITY_MANIFEST_BYTES {
        bail!("identity manifest exceeds size limit");
    }
    let manifest: IdentityManifest = toml::from_str(&encoded)
        .with_context(|| format!("invalid identity manifest {}", path.display()))?;
    manifest.validate()?;
    Ok(manifest)
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

fn resolve_document_paths(document: &mut toml::Value, base: &Path) -> Result<()> {
    let table = document
        .as_table_mut()
        .context("daemon config must be a TOML table")?;
    for key in ["data_dir", "seed_file", "control_socket"] {
        let Some(value) = table.get_mut(key) else {
            continue;
        };
        let text = value
            .as_str()
            .with_context(|| format!("daemon config {key} must be a path string"))?;
        let path = Path::new(text);
        if path.is_relative() {
            let resolved = base.join(path);
            *value = toml::Value::String(
                resolved
                    .to_str()
                    .context("resolved TOML path is not valid UTF-8")?
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn ensure_empty_private_data_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_dir() => {
            bail!("data directory path must be a directory, not a symlink or file")
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .with_context(|| format!("cannot create data directory {}", path.display()))?;
        }
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    if fs::read_dir(path)?.next().transpose()?.is_some() {
        bail!(
            "data directory {} must be empty before initialization",
            path.display()
        );
    }
    Ok(())
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
    fn config_file_paths_are_relative_and_flags_override_values() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("node.toml");
        fs::write(
            &config_path,
            r#"
data_dir = "state"
seed_file = "node.seed"
control_socket = "run/control.sock"
failure_domain = "disk-a"
parity_budget_bytes = 1024
p2p_listen_addresses = ["/ip4/127.0.0.1/udp/1/quic-v1"]
enable_hole_punching = true
"#,
        )
        .unwrap();
        let loaded = read_daemon_options([
            OsString::from("mutualbackupd"),
            OsString::from("--config"),
            config_path.clone().into_os_string(),
            OsString::from("--parity-budget-bytes"),
            OsString::from("2048"),
            OsString::from("--enable-hole-punching"),
            OsString::from("false"),
        ])
        .unwrap();
        assert_eq!(loaded.data_dir, temp.path().join("state"));
        assert_eq!(loaded.seed_file, Some(temp.path().join("node.seed")));
        assert_eq!(loaded.control_socket, temp.path().join("run/control.sock"));
        assert_eq!(loaded.parity_budget_bytes, 2048);
        assert!(!loaded.enable_hole_punching);
        assert_eq!(
            loaded.p2p_listen_addresses,
            ["/ip4/127.0.0.1/udp/1/quic-v1"]
        );
    }

    #[test]
    fn daemon_options_can_be_supplied_only_as_flags() {
        let loaded = read_daemon_options([
            "mutualbackupd",
            "--data-dir",
            "state",
            "--failure-domain",
            "disk-a",
            "--listen",
            "/ip4/127.0.0.1/udp/1/quic-v1",
            "--max-connections",
            "7",
            "--bootstrap",
            "/ip4/127.0.0.1/udp/2/quic-v1",
            "--bootstrap",
            "/ip4/127.0.0.1/udp/3/quic-v1",
        ])
        .unwrap();
        assert_eq!(loaded.data_dir, Path::new("state"));
        assert_eq!(loaded.max_connections, 7);
        assert_eq!(loaded.parity_budget_bytes, DEFAULT_PARITY_BUDGET_BYTES);
        assert!(loaded.enable_hole_punching);
        assert!(loaded.enable_dht_maintenance);
        assert_eq!(
            loaded.p2p_bootstrap_addresses,
            [
                "/ip4/127.0.0.1/udp/2/quic-v1",
                "/ip4/127.0.0.1/udp/3/quic-v1"
            ]
        );
    }

    #[test]
    fn daemon_config_rejects_unknown_fields() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("node.toml");
        fs::write(
            &config_path,
            r#"
data_dir = "state"
failure_domain = "disk-a"
p2p_listen_addresses = ["/ip4/127.0.0.1/udp/1/quic-v1"]
misspelled_budget = 1024
"#,
        )
        .unwrap();
        assert!(
            read_daemon_options([
                OsString::from("mutualbackupd"),
                OsString::from("--config"),
                config_path.into_os_string(),
            ])
            .is_err()
        );
    }

    #[test]
    fn identity_manifest_is_application_owned_and_no_replace() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("state");
        let seed = Seed::from_recovery_string("correct-horse-battery-staple-2026!").unwrap();
        let expected = initialize_identity(&data_dir, &seed, InitializationIntent::New).unwrap();
        assert_eq!(read_identity_manifest(&data_dir).unwrap(), expected);
        assert!(initialize_identity(&data_dir, &seed, InitializationIntent::Recovery).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(identity_manifest_path(&data_dir))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn initialization_intent_controls_failure_domain_requirement() {
        let options = read_daemon_options([
            "mutualbackupd",
            "--data-dir",
            "state",
            "--listen",
            "/ip4/127.0.0.1/udp/1/quic-v1",
        ])
        .unwrap();
        let seed = Seed::from_recovery_string("correct-horse-battery-staple-2026!").unwrap();
        let expected_node_id = mb_core::KeyMaterial::from_seed(&seed).node_id();
        let new_identity = IdentityManifest {
            format_version: 1,
            expected_node_id,
            intent: InitializationIntent::New,
        };
        assert!(options.validate(&new_identity).is_err());
        let recovery_identity = IdentityManifest {
            intent: InitializationIntent::Recovery,
            ..new_identity
        };
        options.validate(&recovery_identity).unwrap();
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
