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

    /// Ignore a configured seed file and start locked.
    #[conf(flag, long = "locked", serde(skip))]
    #[serde(skip)]
    pub start_locked: bool,

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

    /// Clear every listen address inherited from the configuration file.
    #[conf(flag, long = "clear-listen", serde(skip))]
    #[serde(skip)]
    pub clear_p2p_listen_addresses: bool,

    /// Public QUIC multiaddress; repeat for multiple advertised addresses.
    #[conf(
        repeat,
        long = "external-address",
        serde(rename = "p2p_external_addresses")
    )]
    pub p2p_external_addresses: Vec<String>,

    /// Clear every external address inherited from the configuration file.
    #[conf(flag, long = "clear-external-addresses", serde(skip))]
    #[serde(skip)]
    pub clear_p2p_external_addresses: bool,

    /// Bootstrap multiaddress ending in /p2p/PEER_ID; repeat as needed.
    #[conf(repeat, long = "bootstrap", serde(rename = "p2p_bootstrap_addresses"))]
    pub p2p_bootstrap_addresses: Vec<String>,

    /// Clear every bootstrap address inherited from the configuration file.
    #[conf(flag, long = "clear-bootstrap", serde(skip))]
    #[serde(skip)]
    pub clear_p2p_bootstrap_addresses: bool,

    /// Relay multiaddress ending in /p2p/PEER_ID; repeat as needed.
    #[conf(repeat, long = "relay", serde(rename = "p2p_relay_addresses"))]
    pub p2p_relay_addresses: Vec<String>,

    /// Clear every relay address inherited from the configuration file.
    #[conf(flag, long = "clear-relay", serde(skip))]
    #[serde(skip)]
    pub clear_p2p_relay_addresses: bool,

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
    fn apply_cli_clears(&mut self) {
        if self.start_locked {
            self.seed_file = None;
        }
        if self.clear_p2p_listen_addresses {
            self.p2p_listen_addresses.clear();
        }
        if self.clear_p2p_external_addresses {
            self.p2p_external_addresses.clear();
        }
        if self.clear_p2p_bootstrap_addresses {
            self.p2p_bootstrap_addresses.clear();
        }
        if self.clear_p2p_relay_addresses {
            self.p2p_relay_addresses.clear();
        }
    }

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
                path.parent().unwrap_or_else(|| Path::new(".")),
            )
            .map_err(DaemonOptionsError::Load)?;
            let mut options = builder
                .doc(canonical_path.display().to_string(), document)
                .try_parse()
                .map_err(DaemonOptionsError::Parse)?;
            options.apply_cli_clears();
            Ok(options)
        }
        None => {
            let mut options = builder.try_parse().map_err(DaemonOptionsError::Parse)?;
            options.apply_cli_clears();
            Ok(options)
        }
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
    let manifest = IdentityManifest {
        format_version: 1,
        expected_node_id: mb_core::KeyMaterial::from_seed(seed).node_id(),
        intent,
    };
    manifest.validate()?;
    let encoded = toml::to_string_pretty(&manifest)?;
    ensure_initializable_private_data_dir(data_dir, encoded.as_bytes())?;
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
    let parent = containing_directory(path);
    if !parent.is_dir() {
        bail!("{label} parent directory does not exist");
    }
    cleanup_verified_private_temporaries(path, bytes)?;
    if existing_private_file_matches(path, bytes)? == Some(true) {
        sync_directory(parent)?;
        return Ok(());
    }
    if fs::symlink_metadata(path).is_ok() {
        bail!(
            "cannot install {label} {}: target already exists with different contents",
            path.display()
        );
    }
    let temporary = private_temporary_path(path);
    let mut temporary_guard = TemporaryPrivateFile::new(temporary.clone());
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
        if error.kind() == std::io::ErrorKind::AlreadyExists
            && existing_private_file_matches(path, bytes)? == Some(true)
        {
            fs::remove_file(&temporary)
                .with_context(|| format!("cannot remove redundant {label} temporary file"))?;
            temporary_guard.disarm();
            sync_directory(parent)?;
            return Ok(());
        }
        return Err(error).with_context(|| format!("cannot install {label} {}", path.display()));
    }
    sync_directory(parent)?;
    fs::remove_file(&temporary)
        .with_context(|| format!("cannot remove installed {label} temporary file"))?;
    temporary_guard.disarm();
    sync_directory(parent)?;
    Ok(())
}

struct TemporaryPrivateFile {
    path: PathBuf,
    armed: bool,
}

impl TemporaryPrivateFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryPrivateFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
            let _ = sync_directory(containing_directory(&self.path));
        }
    }
}

fn containing_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn previous_private_temporary_prefix(path: &Path) -> String {
    let target = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("private-file");
    format!(".mutualbackup-{target}-")
}

fn private_temporary_prefix(path: &Path) -> String {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;

    // Bind cleanup to the exact target name without putting a fast verifier
    // for private contents (especially the recovery string) in the directory.
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup private temporary v1");
    #[cfg(unix)]
    hasher.update(path.file_name().unwrap_or(path.as_os_str()).as_bytes());
    #[cfg(not(unix))]
    hasher.update(
        path.file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .as_bytes(),
    );
    format!(".mutualbackup-private-{}-", hasher.finalize().to_hex())
}

fn private_temporary_path(path: &Path) -> PathBuf {
    containing_directory(path).join(format!(
        "{}{}.tmp",
        private_temporary_prefix(path),
        Uuid::new_v4()
    ))
}

#[derive(Clone, Copy)]
enum PrivateTemporaryKind {
    Current,
    Previous,
}

fn private_temporary_kind(name: &str, path: &Path) -> Option<PrivateTemporaryKind> {
    let has_uuid_suffix = |prefix: &str| {
        name.strip_prefix(prefix)
            .and_then(|suffix| suffix.strip_suffix(".tmp"))
            .is_some_and(|uuid| Uuid::parse_str(uuid).is_ok())
    };
    if has_uuid_suffix(&private_temporary_prefix(path)) {
        return Some(PrivateTemporaryKind::Current);
    }
    if has_uuid_suffix(&previous_private_temporary_prefix(path)) {
        return Some(PrivateTemporaryKind::Previous);
    }
    let legacy = name
        .strip_prefix(".mutualbackup-")
        .and_then(|suffix| suffix.strip_suffix(".tmp"))
        .is_some_and(|uuid| Uuid::parse_str(uuid).is_ok());
    legacy.then_some(PrivateTemporaryKind::Previous)
}

fn verified_private_temporary(
    path: &Path,
    kind: PrivateTemporaryKind,
    bytes: &[u8],
) -> Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        bail!(
            "private temporary {} must be a regular file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            bail!(
                "private temporary {} must be private and owned by the current user",
                path.display()
            );
        }
    }
    match kind {
        PrivateTemporaryKind::Current => Ok(true),
        PrivateTemporaryKind::Previous => {
            Ok(existing_private_file_matches(path, bytes)? == Some(true))
        }
    }
}

fn cleanup_verified_private_temporaries(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = containing_directory(path);
    if !parent.is_dir() {
        return Ok(());
    }
    let mut removed = false;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(kind) = private_temporary_kind(name, path) else {
            continue;
        };
        if verified_private_temporary(&entry.path(), kind, bytes)? {
            fs::remove_file(entry.path())?;
            removed = true;
        }
    }
    if removed {
        sync_directory(parent)?;
    }
    Ok(())
}

fn existing_private_file_matches(path: &Path, bytes: &[u8]) -> Result<Option<bool>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() {
        bail!("private output {} must be a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!(
                "private output {} must be owned by the current user",
                path.display()
            );
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "private output {} must not be accessible by group or others",
                path.display()
            );
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let mut actual = Vec::new();
    Read::by_ref(&mut file)
        .take((bytes.len() + 1) as u64)
        .read_to_end(&mut actual)?;
    Ok(Some(actual == bytes))
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

fn ensure_initializable_private_data_dir(path: &Path, manifest: &[u8]) -> Result<()> {
    let created = match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_dir() => {
            bail!("data directory path must be a directory, not a symlink or file")
        }
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.uid() != unsafe { libc::geteuid() } {
                    bail!("data directory must be owned by the current user");
                }
            }
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = containing_directory(path);
            fs::create_dir_all(parent).with_context(|| {
                format!("cannot create data directory parent {}", parent.display())
            })?;
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(path)
                .with_context(|| format!("cannot create data directory {}", path.display()))?;
            sync_directory(parent)?;
            true
        }
        Err(error) => return Err(error.into()),
    };

    let manifest_path = identity_manifest_path(path);
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.path() == manifest_path {
            if existing_private_file_matches(&manifest_path, manifest)? != Some(true) {
                bail!("data directory already contains a different identity manifest");
            }
            continue;
        }
        let name = entry.file_name();
        let verified_temporary = name
            .to_str()
            .and_then(|name| private_temporary_kind(name, &manifest_path))
            .map(|kind| verified_private_temporary(&entry.path(), kind, manifest))
            .transpose()?
            .unwrap_or(false);
        if !verified_temporary {
            bail!(
                "data directory {} must be empty before initialization",
                path.display()
            );
        }
    }
    cleanup_verified_private_temporaries(&manifest_path, manifest)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !created {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    sync_directory(path)?;
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
    fn command_line_can_clear_optional_and_repeat_config_values() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("node.toml");
        fs::write(
            &config_path,
            r#"
data_dir = "state"
seed_file = "node.seed"
control_socket = "run/control.sock"
failure_domain = "disk-a"
p2p_listen_addresses = ["/ip4/127.0.0.1/udp/1/quic-v1"]
p2p_external_addresses = ["/ip4/127.0.0.1/udp/2/quic-v1"]
p2p_bootstrap_addresses = ["/ip4/127.0.0.1/udp/3/quic-v1"]
p2p_relay_addresses = ["/ip4/127.0.0.1/udp/4/quic-v1"]
"#,
        )
        .unwrap();
        let loaded = read_daemon_options([
            OsString::from("mutualbackupd"),
            OsString::from("--config"),
            config_path.into_os_string(),
            OsString::from("--locked"),
            OsString::from("--clear-listen"),
            OsString::from("--clear-external-addresses"),
            OsString::from("--clear-bootstrap"),
            OsString::from("--clear-relay"),
        ])
        .unwrap();
        assert_eq!(loaded.seed_file, None);
        assert!(loaded.p2p_listen_addresses.is_empty());
        assert!(loaded.p2p_external_addresses.is_empty());
        assert!(loaded.p2p_bootstrap_addresses.is_empty());
        assert!(loaded.p2p_relay_addresses.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_config_paths_are_relative_to_the_operator_path() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target_dir = temp.path().join("package");
        let operator_dir = temp.path().join("etc");
        fs::create_dir(&target_dir).unwrap();
        fs::create_dir(&operator_dir).unwrap();
        let target = target_dir.join("node.toml");
        fs::write(
            &target,
            r#"
data_dir = "state"
failure_domain = "disk-a"
p2p_listen_addresses = ["/ip4/127.0.0.1/udp/1/quic-v1"]
"#,
        )
        .unwrap();
        let operator_path = operator_dir.join("node.toml");
        symlink(&target, &operator_path).unwrap();
        let loaded = read_daemon_options([
            OsString::from("mutualbackupd"),
            OsString::from("--config"),
            operator_path.into_os_string(),
        ])
        .unwrap();
        assert_eq!(loaded.data_dir, operator_dir.join("state"));
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
        assert_eq!(
            initialize_identity(&data_dir, &seed, InitializationIntent::New).unwrap(),
            expected
        );
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

    #[cfg(unix)]
    #[test]
    fn rejected_nonempty_data_directory_keeps_its_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("state");
        fs::create_dir(&data_dir).unwrap();
        fs::write(data_dir.join("belongs-to-user"), b"keep").unwrap();
        let seed = Seed::from_recovery_string("correct-horse-battery-staple-2026!").unwrap();
        let manifest = IdentityManifest {
            format_version: 1,
            expected_node_id: mb_core::KeyMaterial::from_seed(&seed).node_id(),
            intent: InitializationIntent::New,
        };
        let manifest_bytes = toml::to_string_pretty(&manifest).unwrap().into_bytes();
        let interrupted_temporary = private_temporary_path(&identity_manifest_path(&data_dir));
        fs::write(&interrupted_temporary, &manifest_bytes[..8]).unwrap();
        fs::set_permissions(&interrupted_temporary, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(initialize_identity(&data_dir, &seed, InitializationIntent::New).is_err());
        assert_eq!(
            fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert_eq!(fs::read(data_dir.join("belongs-to-user")).unwrap(), b"keep");
        assert!(interrupted_temporary.exists());
    }

    #[test]
    fn bare_private_output_uses_the_current_directory() {
        assert_eq!(containing_directory(Path::new("node.seed")), Path::new("."));
        assert_eq!(containing_directory(Path::new("state")), Path::new("."));
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

    #[test]
    fn private_write_removes_only_matching_app_temporaries() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("recovery.txt");
        let recovery = "correct-horse-battery-staple-2026!";
        let interrupted = private_temporary_path(&path);
        let matching = temp
            .path()
            .join(format!(".mutualbackup-{}.tmp", Uuid::new_v4()));
        let different = temp
            .path()
            .join(format!(".mutualbackup-{}.tmp", Uuid::new_v4()));
        fs::write(&interrupted, &recovery.as_bytes()[..8]).unwrap();
        fs::write(&matching, recovery).unwrap();
        fs::write(&different, "different-private-content").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&interrupted, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(&matching, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(&different, fs::Permissions::from_mode(0o600)).unwrap();
        }
        write_seed(&path, recovery).unwrap();
        assert!(!interrupted.exists());
        assert!(!matching.exists());
        assert!(different.exists());
    }
}
