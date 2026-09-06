use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use mb_core::{
    KeyMaterial, SectorId, SectorPurpose, SectorRef, SignedRecord, UserRevision, V1_CIPHER_PROFILE,
    V1_SECTOR_SIZE, canonical_bytes, crypt_sector, decode_canonical, encrypted_sector,
    make_sector_id, sector_root,
};
use mb_store::{AnchorFileLocator, CapturedEntry, ControlStore, ReflinkAnchor};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PrivateEntry {
    Directory {
        path: String,
        mode: u32,
        modified_secs: i64,
        modified_nanos: u32,
    },
    File {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        sectors: Vec<SectorRef>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateMetadata {
    pub format_version: u16,
    pub root_mode: u32,
    pub root_modified_secs: i64,
    pub root_modified_nanos: u32,
    pub entries: Vec<PrivateEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct LocalSectorRecipe {
    guild_id: [u8; 32],
    reference: SectorRef,
    source: LocalPlaintextSource,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum LocalPlaintextSource {
    AnchorFile {
        locator: AnchorFileLocator,
        offset: u64,
    },
    Inline(Vec<u8>),
}

struct PendingAnchor {
    manifest: mb_store::AnchorManifest,
    committed: bool,
}

impl PendingAnchor {
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PendingAnchor {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.manifest.remove();
        }
    }
}

pub(crate) fn prepare_revision(
    control: &mut ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    source_root: &Path,
    sequence: u64,
    revision_id: Option<Uuid>,
) -> Result<SignedRecord<UserRevision>> {
    let revision_id = revision_id.unwrap_or_else(Uuid::new_v4);
    if let Some(bytes) = control.get_record("user-revision", revision_id.as_bytes())? {
        let existing: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
        existing.verify(b"mutualbackup/user-revision/v1")?;
        if existing.value.revision_id != revision_id
            || existing.value.owner != keys.node_id()
            || existing.value.guild_id != guild_id
            || existing.value.sequence != sequence
        {
            bail!("persisted revision does not match the retried operation");
        }
        return Ok(existing);
    }
    let parent = match control.get_record("user-revision-head", &guild_id)? {
        Some(bytes) => {
            let previous: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
            previous.verify(b"mutualbackup/user-revision/v1")?;
            if previous.signer != keys.node_id()
                || previous.value.owner != keys.node_id()
                || previous.value.guild_id != guild_id
                || previous.value.format_version != 1
                || previous.value.cipher_profile != V1_CIPHER_PROFILE
                || previous.value.sequence.checked_add(1) != Some(sequence)
            {
                bail!("new revision does not extend the durable local revision head");
            }
            Some(previous.value.hash()?)
        }
        None if sequence == 1 => None,
        None => bail!("the first local revision must have sequence one"),
    };
    let mut anchor = PendingAnchor {
        manifest: ReflinkAnchor::capture(source_root).context("capture reflink source anchor")?,
        committed: false,
    };
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut data_references = Vec::new();
    let mut private_entries = Vec::new();
    let mut recipe_records = Vec::with_capacity(256);
    let mut ordinal = 0_u64;

    for entry in &anchor.manifest.entries {
        match entry {
            CapturedEntry::Directory {
                path,
                mode,
                modified_secs,
                modified_nanos,
            } => {
                private_entries.push(PrivateEntry::Directory {
                    path: path.clone(),
                    mode: *mode,
                    modified_secs: *modified_secs,
                    modified_nanos: *modified_nanos,
                });
            }
            CapturedEntry::File {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
            } => {
                let locator = anchor.manifest.file_locator(path.clone())?;
                let mut file = locator.open().context("open captured anchor file")?;
                let mut remaining = *logical_len;
                let mut offset = 0_u64;
                let mut file_references = Vec::new();
                while remaining > 0 {
                    let logical_len = remaining.min(V1_SECTOR_SIZE as u64) as usize;
                    let mut plaintext = vec![0_u8; logical_len];
                    file.read_exact(&mut plaintext)?;
                    let id =
                        make_sector_id(keys.node_id(), revision_id, SectorPurpose::Data, ordinal);
                    ordinal += 1;
                    let (reference, _) = encrypted_sector(&encryption_key, id, &plaintext)?;
                    data_references.push(reference.clone());
                    file_references.push(reference.clone());
                    queue_recipe(
                        control,
                        &mut recipe_records,
                        LocalSectorRecipe {
                            guild_id,
                            reference,
                            source: LocalPlaintextSource::AnchorFile {
                                locator: locator.clone(),
                                offset,
                            },
                        },
                    )?;
                    offset += logical_len as u64;
                    remaining -= logical_len as u64;
                }
                private_entries.push(PrivateEntry::File {
                    path: path.clone(),
                    mode: *mode,
                    logical_len: *logical_len,
                    modified_secs: *modified_secs,
                    modified_nanos: *modified_nanos,
                    sectors: file_references,
                });
            }
        }
    }

    let metadata = PrivateMetadata {
        format_version: 1,
        root_mode: anchor.manifest.root_mode,
        root_modified_secs: anchor.manifest.root_modified_secs,
        root_modified_nanos: anchor.manifest.root_modified_nanos,
        entries: private_entries,
    };
    let metadata_bytes = canonical_bytes(&metadata)?;
    let mut metadata_references = Vec::new();
    for (metadata_ordinal, plaintext) in metadata_bytes.chunks(V1_SECTOR_SIZE).enumerate() {
        let id = make_sector_id(
            keys.node_id(),
            revision_id,
            SectorPurpose::Metadata,
            metadata_ordinal as u64,
        );
        let (reference, _) = encrypted_sector(&encryption_key, id, plaintext)?;
        metadata_references.push(reference.clone());
        queue_recipe(
            control,
            &mut recipe_records,
            LocalSectorRecipe {
                guild_id,
                reference,
                source: LocalPlaintextSource::Inline(plaintext.to_vec()),
            },
        )?;
    }

    let revision = SignedRecord::sign(
        b"mutualbackup/user-revision/v1",
        UserRevision {
            format_version: 1,
            guild_id,
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id,
            owner: keys.node_id(),
            sequence,
            parent,
            metadata_sectors: metadata_references,
            data_sectors: data_references,
        },
        keys,
    )?;
    if !recipe_records.is_empty() {
        control.put_records(&recipe_records)?;
    }
    let records = vec![
        (
            "anchor-manifest".to_owned(),
            revision_id.as_bytes().to_vec(),
            canonical_bytes(&anchor.manifest)?,
        ),
        (
            "user-revision".to_owned(),
            revision_id.as_bytes().to_vec(),
            canonical_bytes(&revision)?,
        ),
        (
            "user-revision-head".to_owned(),
            guild_id.to_vec(),
            canonical_bytes(&revision)?,
        ),
    ];
    control.put_records(&records)?;
    anchor.commit();
    Ok(revision)
}

fn queue_recipe(
    control: &mut ControlStore,
    records: &mut Vec<(String, Vec<u8>, Vec<u8>)>,
    recipe: LocalSectorRecipe,
) -> Result<()> {
    records.push((
        "local-sector".to_owned(),
        recipe.reference.id.to_vec(),
        canonical_bytes(&recipe)?,
    ));
    if records.len() == records.capacity() {
        control.put_records(records)?;
        records.clear();
    }
    Ok(())
}

pub(crate) fn install_inline_recipe(
    control: &mut ControlStore,
    guild_id: [u8; 32],
    reference: SectorRef,
    plaintext: Vec<u8>,
) -> Result<()> {
    let recipe = LocalSectorRecipe {
        guild_id,
        reference: reference.clone(),
        source: LocalPlaintextSource::Inline(plaintext),
    };
    control.put_record("local-sector", &reference.id, &canonical_bytes(&recipe)?)?;
    Ok(())
}

pub(crate) fn install_recovered_sector_recipe(
    control: &mut ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    reference: SectorRef,
    ciphertext: &[u8],
) -> Result<()> {
    if reference.logical_len as usize > V1_SECTOR_SIZE
        || ciphertext.len() != V1_SECTOR_SIZE
        || sector_root(ciphertext) != reference.root
    {
        bail!("recovered information shard does not match its descriptor");
    }
    let mut plaintext = ciphertext.to_vec();
    crypt_sector(
        &keys.guild_data_key(&guild_id),
        reference.id,
        &mut plaintext,
    )?;
    plaintext.truncate(reference.logical_len as usize);
    install_inline_recipe(control, guild_id, reference, plaintext)
}

pub(crate) fn render_sector(
    control: &ControlStore,
    keys: &KeyMaterial,
    sector_id: &SectorId,
    expected_guild: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    let encoded = control
        .get_record("local-sector", sector_id)?
        .context("local sector recipe is unavailable")?;
    let recipe: LocalSectorRecipe = decode_canonical(&encoded)?;
    if expected_guild.is_some_and(|guild_id| recipe.guild_id != *guild_id) {
        bail!("local sector does not belong to the requested guild");
    }
    let plaintext = match &recipe.source {
        LocalPlaintextSource::AnchorFile { locator, offset } => {
            let mut file = locator.open().context("open source anchor")?;
            file.seek(SeekFrom::Start(*offset))?;
            let mut plaintext = vec![0_u8; recipe.reference.logical_len as usize];
            file.read_exact(&mut plaintext)?;
            plaintext
        }
        LocalPlaintextSource::Inline(bytes) => bytes.clone(),
    };
    let (actual_reference, ciphertext) = encrypted_sector(
        &keys.guild_data_key(&recipe.guild_id),
        recipe.reference.id,
        &plaintext,
    )?;
    if actual_reference != recipe.reference {
        bail!("source anchor no longer matches the committed sector root");
    }
    Ok(ciphertext)
}

pub fn restore_revision(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    ciphertexts: &BTreeMap<SectorId, Vec<u8>>,
    target: &Path,
) -> Result<()> {
    restore_revision_from_source(keys, guild_id, revision, target, |sector_id| {
        ciphertexts
            .get(sector_id)
            .cloned()
            .with_context(|| format!("missing recovered sector {}", hex_id(sector_id)))
    })
}

pub fn restore_revision_from_source<F>(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    target: &Path,
    mut load_ciphertext: F,
) -> Result<()>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    if target.exists() {
        bail!("restore target already exists: {}", target.display());
    }
    let parent = target.parent().context("restore target has no parent")?;
    fs::create_dir_all(parent)?;
    let staging = parent.join(format!(".mutualbackup-restore-{}", Uuid::new_v4()));
    build_revision_restore(keys, guild_id, revision, &staging, &mut load_ciphertext)?;
    publish_restore(&staging, target)
}

pub(crate) fn build_revision_restore<F>(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    staging: &Path,
    load_ciphertext: &mut F,
) -> Result<()>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    revision.verify(b"mutualbackup/user-revision/v1")?;
    if revision.signer != keys.node_id()
        || revision.value.owner != keys.node_id()
        || revision.value.guild_id != guild_id
        || revision.value.format_version != 1
        || revision.value.cipher_profile != V1_CIPHER_PROFILE
    {
        bail!("revision does not belong to the recovering seed and guild");
    }
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut metadata_bytes = Vec::new();
    for reference in &revision.value.metadata_sectors {
        metadata_bytes.extend(decrypt_reference(
            &encryption_key,
            reference,
            load_ciphertext,
        )?);
    }
    let metadata: PrivateMetadata = decode_canonical(&metadata_bytes)?;
    if metadata.format_version != 1 {
        bail!("unsupported private metadata version");
    }

    create_private_dir(staging)?;
    let result = restore_entries(staging, &metadata, &encryption_key, load_ciphertext);
    if let Err(error) = result {
        let _ = fs::remove_dir_all(staging);
        return Err(error);
    }
    sync_tree_bottom_up(staging)?;
    Ok(())
}

pub(crate) fn publish_restore(staging: &Path, target: &Path) -> Result<()> {
    let parent = target.parent().context("restore target has no parent")?;
    rename_no_replace(staging, target)?;
    sync_directory(parent)?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn native_directory_id(path: &Path) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("restore object is not a directory");
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
pub(crate) fn native_directory_id(_path: &Path) -> Result<(u64, u64)> {
    bail!("native restore identity is not implemented on this platform")
}

fn restore_entries<F>(
    staging: &Path,
    metadata: &PrivateMetadata,
    encryption_key: &[u8; 32],
    load_ciphertext: &mut F,
) -> Result<()>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    let mut directory_metadata = Vec::new();
    for entry in &metadata.entries {
        match entry {
            PrivateEntry::Directory {
                path,
                mode,
                modified_secs,
                modified_nanos,
            } => {
                let destination = safe_join(staging, path)?;
                create_private_dir(&destination)?;
                directory_metadata.push((destination, *mode, *modified_secs, *modified_nanos));
            }
            PrivateEntry::File {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                sectors,
            } => {
                let destination = safe_join(staging, path)?;
                if let Some(parent) = destination.parent() {
                    create_private_dir(parent)?;
                }
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&destination)?;
                let mut written = 0_u64;
                for reference in sectors {
                    let plaintext = decrypt_reference(encryption_key, reference, load_ciphertext)?;
                    file.write_all(&plaintext)?;
                    written += plaintext.len() as u64;
                }
                if written != *logical_len {
                    bail!("restored file length does not match signed metadata");
                }
                set_metadata_durable(&file, &destination, *mode, *modified_secs, *modified_nanos)?;
            }
        }
    }
    directory_metadata.push((
        staging.to_path_buf(),
        metadata.root_mode,
        metadata.root_modified_secs,
        metadata.root_modified_nanos,
    ));
    directory_metadata.sort_by_key(|(path, ..)| std::cmp::Reverse(path.components().count()));
    for (path, mode, modified_secs, modified_nanos) in directory_metadata {
        let directory = File::open(&path)?;
        set_metadata_durable(&directory, &path, mode, modified_secs, modified_nanos)?;
    }
    Ok(())
}

fn decrypt_reference<F>(
    encryption_key: &[u8; 32],
    reference: &SectorRef,
    load_ciphertext: &mut F,
) -> Result<Vec<u8>>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    let mut bytes = load_ciphertext(&reference.id)?;
    if bytes.len() != V1_SECTOR_SIZE || sector_root(&bytes) != reference.root {
        bail!("recovered sector failed its signed root");
    }
    crypt_sector(encryption_key, reference.id, &mut bytes)?;
    let logical_len = reference.logical_len as usize;
    if logical_len > bytes.len() {
        bail!("invalid logical sector length");
    }
    bytes.truncate(logical_len);
    Ok(bytes)
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("unsafe path in recovered metadata");
    }
    Ok(root.join(relative))
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn set_metadata_durable(
    file: &File,
    path: &Path,
    mode: u32,
    modified_secs: i64,
    modified_nanos: u32,
) -> Result<()> {
    if modified_nanos >= 1_000_000_000 {
        bail!("invalid modification timestamp");
    }
    set_mode(path, mode)?;
    filetime::set_file_mtime(
        path,
        filetime::FileTime::from_unix_time(modified_secs, modified_nanos),
    )?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    let _ = path;
    Ok(())
}

fn sync_tree_bottom_up(root: &Path) -> Result<()> {
    let mut directories = walkdir::WalkDir::new(root)
        .min_depth(0)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| entry.file_type().is_dir())
        .map(|entry| entry.into_path())
        .collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in directories {
        sync_directory(&path)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename_no_replace(source: &Path, destination: &Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let source = CString::new(source.as_os_str().as_bytes())?;
    let destination = CString::new(destination.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == -1 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
fn rename_no_replace(_source: &Path, _destination: &Path) -> Result<()> {
    bail!("atomic no-replace restore is currently implemented only on Linux")
}

fn hex_id(id: &[u8; 32]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}
