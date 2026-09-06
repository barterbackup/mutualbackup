use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use mb_core::{
    KeyMaterial, SectorId, SectorPurpose, SectorRef, SignedRecord, UserRevision, V1_SECTOR_SIZE,
    canonical_bytes, crypt_sector, decode_canonical, encrypted_sector, make_sector_id, sector_root,
};
use mb_store::{CapturedEntry, ControlStore, ReflinkAnchor};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PrivateEntry {
    Directory {
        path: String,
        mode: u32,
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
    AnchorFile { path: PathBuf, offset: u64 },
    Inline(Vec<u8>),
}

pub(crate) fn prepare_revision(
    control: &mut ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    source_root: &Path,
    sequence: u64,
) -> Result<SignedRecord<UserRevision>> {
    let anchor = ReflinkAnchor::capture(source_root).context("capture reflink source anchor")?;
    let revision_id = Uuid::new_v4();
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut data_references = Vec::new();
    let mut private_entries = Vec::new();
    let mut recipes = Vec::new();
    let mut ordinal = 0_u64;

    for entry in &anchor.entries {
        match entry {
            CapturedEntry::Directory { path, mode } => {
                private_entries.push(PrivateEntry::Directory {
                    path: path.clone(),
                    mode: *mode,
                });
            }
            CapturedEntry::File {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
            } => {
                let anchor_path = anchor.anchor_root.join(path);
                let mut file = File::open(&anchor_path)
                    .with_context(|| format!("open captured file {}", anchor_path.display()))?;
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
                    recipes.push(LocalSectorRecipe {
                        guild_id,
                        reference,
                        source: LocalPlaintextSource::AnchorFile {
                            path: anchor_path.clone(),
                            offset,
                        },
                    });
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
        recipes.push(LocalSectorRecipe {
            guild_id,
            reference,
            source: LocalPlaintextSource::Inline(plaintext.to_vec()),
        });
    }

    let revision = SignedRecord::sign(
        b"mutualbackup/user-revision/v1",
        UserRevision {
            format_version: 1,
            revision_id,
            owner: keys.node_id(),
            sequence,
            parent: None,
            metadata_sectors: metadata_references,
            data_sectors: data_references,
        },
        keys,
    )?;
    let mut records = recipes
        .iter()
        .map(|recipe| {
            Ok((
                "local-sector".to_owned(),
                recipe.reference.id.to_vec(),
                canonical_bytes(recipe)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    records.push((
        "anchor-manifest".to_owned(),
        revision_id.as_bytes().to_vec(),
        canonical_bytes(&anchor)?,
    ));
    records.push((
        "user-revision".to_owned(),
        revision_id.as_bytes().to_vec(),
        canonical_bytes(&revision)?,
    ));
    control.put_records(&records)?;
    Ok(revision)
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

pub(crate) fn render_sector(
    control: &ControlStore,
    keys: &KeyMaterial,
    sector_id: &SectorId,
) -> Result<Vec<u8>> {
    let encoded = control
        .get_record("local-sector", sector_id)?
        .context("local sector recipe is unavailable")?;
    let recipe: LocalSectorRecipe = decode_canonical(&encoded)?;
    let plaintext = match &recipe.source {
        LocalPlaintextSource::AnchorFile { path, offset } => {
            let mut file = File::open(path)
                .with_context(|| format!("open source anchor {}", path.display()))?;
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
    revision.verify(b"mutualbackup/user-revision/v1")?;
    if revision.signer != keys.node_id() || revision.value.owner != keys.node_id() {
        bail!("revision does not belong to the recovering seed");
    }
    if target.exists() {
        bail!("restore target already exists: {}", target.display());
    }
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut metadata_bytes = Vec::new();
    for reference in &revision.value.metadata_sectors {
        metadata_bytes.extend(decrypt_reference(&encryption_key, reference, ciphertexts)?);
    }
    let metadata: PrivateMetadata = decode_canonical(&metadata_bytes)?;
    if metadata.format_version != 1 {
        bail!("unsupported private metadata version");
    }

    let parent = target.parent().context("restore target has no parent")?;
    fs::create_dir_all(parent)?;
    let staging = parent.join(format!(".mutualbackup-restore-{}", Uuid::new_v4()));
    create_private_dir(&staging)?;
    let result = restore_entries(&staging, &metadata, &encryption_key, ciphertexts);
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    sync_directory(&staging)?;
    fs::rename(&staging, target)?;
    sync_directory(parent)?;
    Ok(())
}

fn restore_entries(
    staging: &Path,
    metadata: &PrivateMetadata,
    encryption_key: &[u8; 32],
    ciphertexts: &BTreeMap<SectorId, Vec<u8>>,
) -> Result<()> {
    let mut directory_modes = Vec::new();
    for entry in &metadata.entries {
        match entry {
            PrivateEntry::Directory { path, mode } => {
                let destination = safe_join(staging, path)?;
                create_private_dir(&destination)?;
                directory_modes.push((destination, *mode));
            }
            PrivateEntry::File {
                path,
                mode,
                logical_len,
                sectors,
                ..
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
                    let plaintext = decrypt_reference(encryption_key, reference, ciphertexts)?;
                    file.write_all(&plaintext)?;
                    written += plaintext.len() as u64;
                }
                if written != *logical_len {
                    bail!("restored file length does not match signed metadata");
                }
                file.sync_all()?;
                set_mode(&destination, *mode)?;
            }
        }
    }
    directory_modes.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode) in directory_modes {
        set_mode(&path, mode)?;
    }
    Ok(())
}

fn decrypt_reference(
    encryption_key: &[u8; 32],
    reference: &SectorRef,
    ciphertexts: &BTreeMap<SectorId, Vec<u8>>,
) -> Result<Vec<u8>> {
    let mut bytes = ciphertexts
        .get(&reference.id)
        .with_context(|| format!("missing recovered sector {}", hex_id(&reference.id)))?
        .clone();
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

fn hex_id(id: &[u8; 32]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}
