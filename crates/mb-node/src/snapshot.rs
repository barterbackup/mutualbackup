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
use mb_store::{
    AnchorFileLocator, CapturedEntry, ControlStore, FileExtent, NativeFileId, ReflinkAnchor,
    StableAnchorFileLocator,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

type RecordWrite = (String, Vec<u8>, Vec<u8>);

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
    FileV2 {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        link_group: u64,
        data_extents: Vec<PrivateDataExtent>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateDataExtent {
    pub offset: u64,
    pub logical_len: u64,
    pub sectors: Vec<SectorRef>,
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
    StableAnchorFile {
        locator: StableAnchorFileLocator,
        offset: u64,
    },
}

struct PendingAnchor {
    manifest: mb_store::StableAnchorManifest,
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
    let mut prepared_links = BTreeMap::<NativeFileId, (u64, Vec<PrivateDataExtent>)>::new();
    let mut next_link_group = 0_u64;

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
                            source: LocalPlaintextSource::StableAnchorFile {
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
            CapturedEntry::FileV2 {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                native_id,
                data_extents,
            } => {
                let (link_group, private_extents) =
                    if let Some(existing) = prepared_links.get(native_id) {
                        existing.clone()
                    } else {
                        let locator = anchor.manifest.file_locator(path.clone())?;
                        let extents = prepare_sparse_file(
                            control,
                            &mut recipe_records,
                            keys,
                            guild_id,
                            revision_id,
                            &mut ordinal,
                            &locator,
                            *logical_len,
                            data_extents,
                        )?;
                        for extent in &extents {
                            data_references.extend(extent.sectors.iter().cloned());
                        }
                        let link_group = next_link_group;
                        next_link_group = next_link_group
                            .checked_add(1)
                            .context("too many hard-link groups in one revision")?;
                        prepared_links.insert(*native_id, (link_group, extents.clone()));
                        (link_group, extents)
                    };
                private_entries.push(PrivateEntry::FileV2 {
                    path: path.clone(),
                    mode: *mode,
                    logical_len: *logical_len,
                    modified_secs: *modified_secs,
                    modified_nanos: *modified_nanos,
                    link_group,
                    data_extents: private_extents,
                });
            }
        }
    }

    let metadata = PrivateMetadata {
        format_version: 2,
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

#[allow(clippy::too_many_arguments)]
fn prepare_sparse_file(
    control: &mut ControlStore,
    recipe_records: &mut Vec<RecordWrite>,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision_id: Uuid,
    ordinal: &mut u64,
    locator: &StableAnchorFileLocator,
    logical_len: u64,
    extents: &[FileExtent],
) -> Result<Vec<PrivateDataExtent>> {
    validate_file_extents(
        logical_len,
        extents
            .iter()
            .map(|extent| (extent.offset, extent.logical_len)),
    )?;
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut file = locator.open().context("open captured anchor file")?;
    let mut result = Vec::with_capacity(extents.len());
    for extent in extents {
        file.seek(SeekFrom::Start(extent.offset))?;
        let mut remaining = extent.logical_len;
        let mut offset = extent.offset;
        let mut sectors = Vec::new();
        while remaining > 0 {
            let logical_len = remaining.min(V1_SECTOR_SIZE as u64) as usize;
            let mut plaintext = vec![0_u8; logical_len];
            file.read_exact(&mut plaintext)?;
            let id = make_sector_id(keys.node_id(), revision_id, SectorPurpose::Data, *ordinal);
            *ordinal = ordinal
                .checked_add(1)
                .context("too many sectors in one revision")?;
            let (reference, _) = encrypted_sector(&encryption_key, id, &plaintext)?;
            sectors.push(reference.clone());
            queue_recipe(
                control,
                recipe_records,
                LocalSectorRecipe {
                    guild_id,
                    reference,
                    source: LocalPlaintextSource::StableAnchorFile {
                        locator: locator.clone(),
                        offset,
                    },
                },
            )?;
            offset += logical_len as u64;
            remaining -= logical_len as u64;
        }
        result.push(PrivateDataExtent {
            offset: extent.offset,
            logical_len: extent.logical_len,
            sectors,
        });
    }
    Ok(result)
}

fn validate_file_extents(
    logical_len: u64,
    extents: impl IntoIterator<Item = (u64, u64)>,
) -> Result<()> {
    let mut previous_end = 0_u64;
    for (offset, extent_len) in extents {
        let end = offset
            .checked_add(extent_len)
            .context("file extent overflows its signed range")?;
        if extent_len == 0 || offset < previous_end || end > logical_len {
            bail!("invalid or overlapping file extent");
        }
        previous_end = end;
    }
    Ok(())
}

fn queue_recipe(
    control: &mut ControlStore,
    records: &mut Vec<RecordWrite>,
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

pub(crate) fn reanchor_recovered_revision(
    control: &mut ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    restored_root: &Path,
) -> Result<()> {
    revision.verify(b"mutualbackup/user-revision/v1")?;
    if revision.signer != keys.node_id()
        || revision.value.owner != keys.node_id()
        || revision.value.guild_id != guild_id
    {
        bail!("recovered revision does not belong to the local seed and guild");
    }
    if revision.value.data_sectors.is_empty() {
        return Ok(());
    }
    let metadata = load_private_metadata(control, keys, guild_id, revision)?;
    let existing = control.get_record("anchor-manifest", revision.value.revision_id.as_bytes())?;
    let mut pending = None;
    let manifest = if let Some(bytes) = existing {
        decode_canonical::<mb_store::StableAnchorManifest>(&bytes)?
    } else {
        let anchor = PendingAnchor {
            manifest: ReflinkAnchor::capture(restored_root)
                .context("capture recovered source anchor")?,
            committed: false,
        };
        let manifest = anchor.manifest.clone();
        pending = Some(anchor);
        manifest
    };
    if manifest.format_version != 2 {
        bail!("unsupported recovered anchor manifest version");
    }
    validate_recovered_manifest(&metadata, &manifest)?;
    let mut recipes = recovered_anchor_recipes(keys, guild_id, revision, &metadata, &manifest)?;
    recipes.push((
        "anchor-manifest".to_owned(),
        revision.value.revision_id.as_bytes().to_vec(),
        canonical_bytes(&manifest)?,
    ));
    control.put_records(&recipes)?;
    if let Some(anchor) = pending.as_mut() {
        anchor.commit();
    }
    Ok(())
}

fn load_private_metadata(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
) -> Result<PrivateMetadata> {
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut metadata_bytes = Vec::new();
    for reference in &revision.value.metadata_sectors {
        metadata_bytes.extend(decrypt_reference(
            &encryption_key,
            reference,
            &mut |sector_id| render_sector(control, keys, sector_id, Some(&guild_id)),
        )?);
    }
    let metadata: PrivateMetadata = decode_canonical(&metadata_bytes)?;
    if !matches!(metadata.format_version, 1 | 2) {
        bail!("unsupported private metadata version");
    }
    Ok(metadata)
}

pub(crate) fn restore_signed_root_metadata(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    restored_root: &Path,
) -> Result<()> {
    let metadata = load_private_metadata(control, keys, guild_id, revision)?;
    let directory = File::open(restored_root)?;
    set_metadata_durable(
        &directory,
        restored_root,
        metadata.root_mode,
        metadata.root_modified_secs,
        metadata.root_modified_nanos,
    )
}

fn validate_recovered_manifest(
    metadata: &PrivateMetadata,
    manifest: &mb_store::StableAnchorManifest,
) -> Result<()> {
    if metadata.root_mode != manifest.root_mode
        || metadata.root_modified_secs != manifest.root_modified_secs
        || metadata.root_modified_nanos != manifest.root_modified_nanos
        || metadata.entries.len() != manifest.entries.len()
    {
        bail!("recovered anchor root does not match signed metadata");
    }
    let captured = manifest
        .entries
        .iter()
        .map(|entry| {
            let path = match entry {
                CapturedEntry::Directory { path, .. }
                | CapturedEntry::File { path, .. }
                | CapturedEntry::FileV2 { path, .. } => path,
            };
            (path.as_str(), entry)
        })
        .collect::<BTreeMap<_, _>>();
    if captured.len() != manifest.entries.len() {
        bail!("recovered anchor contains duplicate paths");
    }
    let mut signed_to_captured = BTreeMap::<u64, NativeFileId>::new();
    let mut captured_to_signed = BTreeMap::<NativeFileId, u64>::new();
    for entry in &metadata.entries {
        let path = private_entry_path(entry);
        let actual = captured
            .get(path)
            .with_context(|| format!("recovered anchor is missing {path}"))?;
        match (entry, *actual) {
            (
                PrivateEntry::Directory {
                    mode,
                    modified_secs,
                    modified_nanos,
                    ..
                },
                CapturedEntry::Directory {
                    mode: actual_mode,
                    modified_secs: actual_secs,
                    modified_nanos: actual_nanos,
                    ..
                },
            ) if mode == actual_mode
                && modified_secs == actual_secs
                && modified_nanos == actual_nanos => {}
            (
                PrivateEntry::File {
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    ..
                },
                CapturedEntry::FileV2 {
                    mode: actual_mode,
                    logical_len: actual_len,
                    modified_secs: actual_secs,
                    modified_nanos: actual_nanos,
                    ..
                },
            ) if mode == actual_mode
                && logical_len == actual_len
                && modified_secs == actual_secs
                && modified_nanos == actual_nanos => {}
            (
                PrivateEntry::FileV2 {
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    link_group,
                    data_extents,
                    ..
                },
                CapturedEntry::FileV2 {
                    mode: actual_mode,
                    logical_len: actual_len,
                    modified_secs: actual_secs,
                    modified_nanos: actual_nanos,
                    native_id: actual_native_id,
                    data_extents: actual_extents,
                    ..
                },
            ) if mode == actual_mode
                && logical_len == actual_len
                && modified_secs == actual_secs
                && modified_nanos == actual_nanos
                && data_extents
                    .iter()
                    .map(|extent| FileExtent {
                        offset: extent.offset,
                        logical_len: extent.logical_len,
                    })
                    .eq(actual_extents.iter().cloned()) =>
            {
                if signed_to_captured
                    .insert(*link_group, *actual_native_id)
                    .is_some_and(|previous| previous != *actual_native_id)
                    || captured_to_signed
                        .insert(*actual_native_id, *link_group)
                        .is_some_and(|previous| previous != *link_group)
                {
                    bail!("recovered anchor does not preserve signed hard-link groups");
                }
            }
            _ => bail!("recovered anchor entry {path} does not match signed metadata"),
        }
    }
    Ok(())
}

fn private_entry_path(entry: &PrivateEntry) -> &str {
    match entry {
        PrivateEntry::Directory { path, .. }
        | PrivateEntry::File { path, .. }
        | PrivateEntry::FileV2 { path, .. } => path,
    }
}

fn recovered_anchor_recipes(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    metadata: &PrivateMetadata,
    manifest: &mb_store::StableAnchorManifest,
) -> Result<Vec<RecordWrite>> {
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut by_id = BTreeMap::<SectorId, LocalSectorRecipe>::new();
    for entry in &metadata.entries {
        let (path, extents) = match entry {
            PrivateEntry::Directory { .. } => continue,
            PrivateEntry::File {
                path,
                logical_len,
                sectors,
                ..
            } => (
                path,
                vec![PrivateDataExtent {
                    offset: 0,
                    logical_len: *logical_len,
                    sectors: sectors.clone(),
                }],
            ),
            PrivateEntry::FileV2 {
                path, data_extents, ..
            } => (path, data_extents.clone()),
        };
        let locator = manifest.file_locator(path.clone())?;
        let mut file = locator.open().context("open recovered anchor file")?;
        for extent in extents {
            let mut offset = extent.offset;
            let mut extent_len = 0_u64;
            for reference in extent.sectors {
                file.seek(SeekFrom::Start(offset))?;
                let mut plaintext = vec![0_u8; reference.logical_len as usize];
                file.read_exact(&mut plaintext)?;
                let (actual, _) = encrypted_sector(&encryption_key, reference.id, &plaintext)?;
                if actual != reference {
                    bail!("recovered anchor content does not match a signed sector");
                }
                let recipe = LocalSectorRecipe {
                    guild_id,
                    reference: reference.clone(),
                    source: LocalPlaintextSource::StableAnchorFile {
                        locator: locator.clone(),
                        offset,
                    },
                };
                if by_id
                    .insert(reference.id, recipe.clone())
                    .is_some_and(|previous| previous.reference != recipe.reference)
                {
                    bail!("one sector ID has conflicting signed references");
                }
                offset = offset
                    .checked_add(reference.logical_len as u64)
                    .context("signed sector range overflow")?;
                extent_len = extent_len
                    .checked_add(reference.logical_len as u64)
                    .context("signed extent length overflow")?;
            }
            if extent_len != extent.logical_len {
                bail!("signed extent does not match its sector lengths");
            }
        }
    }
    let expected = revision
        .value
        .data_sectors
        .iter()
        .map(|reference| (reference.id, reference))
        .collect::<BTreeMap<_, _>>();
    if expected.len() != revision.value.data_sectors.len()
        || expected.len() != by_id.len()
        || expected.iter().any(|(id, reference)| {
            by_id.get(id).map(|recipe| &recipe.reference) != Some(*reference)
        })
    {
        bail!("signed data-sector catalog does not match recovered file metadata");
    }
    by_id
        .into_values()
        .map(|recipe| {
            Ok((
                "local-sector".to_owned(),
                recipe.reference.id.to_vec(),
                canonical_bytes(&recipe)?,
            ))
        })
        .collect()
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
        LocalPlaintextSource::StableAnchorFile { locator, offset } => {
            let mut file = locator.open().context("open stable source anchor")?;
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

#[cfg(test)]
pub(crate) fn local_recipe_is_inline(control: &ControlStore, sector_id: &SectorId) -> Result<bool> {
    let encoded = control
        .get_record("local-sector", sector_id)?
        .context("local sector recipe is unavailable")?;
    let recipe: LocalSectorRecipe = decode_canonical(&encoded)?;
    Ok(matches!(recipe.source, LocalPlaintextSource::Inline(_)))
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
    if !matches!(metadata.format_version, 1 | 2) {
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

pub(crate) fn install_recovery_marker(
    root: &Path,
    marker_name: &str,
    marker: &[u8; 32],
) -> Result<()> {
    let path = recovery_marker_path(root, marker_name)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(marker)?;
    file.sync_all()?;
    sync_directory(root)?;
    Ok(())
}

pub(crate) fn verify_recovery_marker(
    root: &Path,
    marker_name: &str,
    expected: &[u8; 32],
) -> Result<()> {
    let path = recovery_marker_path(root, marker_name)?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != 32 {
        bail!("restore ownership marker is not a safe regular file");
    }
    let mut file = open_file_no_follow(&path)?;
    let mut actual = [0_u8; 32];
    file.read_exact(&mut actual)?;
    if actual != *expected {
        bail!("restore ownership marker does not match the durable recovery job");
    }
    Ok(())
}

pub(crate) fn remove_recovery_marker(
    root: &Path,
    marker_name: &str,
    expected: &[u8; 32],
) -> Result<bool> {
    let path = recovery_marker_path(root, marker_name)?;
    if !path.exists() {
        return Ok(false);
    }
    verify_recovery_marker(root, marker_name, expected)?;
    fs::remove_file(path)?;
    sync_directory(root)?;
    Ok(true)
}

fn recovery_marker_path(root: &Path, marker_name: &str) -> Result<PathBuf> {
    let relative = Path::new(marker_name);
    if !marker_name.starts_with(".mutualbackup-recovery-ownership-")
        || relative.components().count() != 1
        || !matches!(relative.components().next(), Some(Component::Normal(_)))
    {
        bail!("invalid recovery ownership marker name");
    }
    Ok(root.join(relative))
}

#[cfg(unix)]
fn open_file_no_follow(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?)
}

#[cfg(not(unix))]
fn open_file_no_follow(path: &Path) -> Result<File> {
    Ok(File::open(path)?)
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
    let mut restored_links = BTreeMap::<u64, RestoredLink>::new();
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
            PrivateEntry::FileV2 {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                link_group,
                data_extents,
            } => {
                let destination = safe_join(staging, path)?;
                if let Some(parent) = destination.parent() {
                    create_private_dir(parent)?;
                }
                if let Some(existing) = restored_links.get(link_group) {
                    if existing.mode != *mode
                        || existing.logical_len != *logical_len
                        || existing.modified_secs != *modified_secs
                        || existing.modified_nanos != *modified_nanos
                        || existing.data_extents != *data_extents
                    {
                        bail!("hard-linked aliases have inconsistent signed metadata");
                    }
                    fs::hard_link(&existing.path, &destination)?;
                } else {
                    restore_sparse_file(
                        &destination,
                        *logical_len,
                        data_extents,
                        encryption_key,
                        load_ciphertext,
                    )?;
                    let file = File::open(&destination)?;
                    set_metadata_durable(
                        &file,
                        &destination,
                        *mode,
                        *modified_secs,
                        *modified_nanos,
                    )?;
                    restored_links.insert(
                        *link_group,
                        RestoredLink {
                            path: destination,
                            mode: *mode,
                            logical_len: *logical_len,
                            modified_secs: *modified_secs,
                            modified_nanos: *modified_nanos,
                            data_extents: data_extents.clone(),
                        },
                    );
                }
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

struct RestoredLink {
    path: PathBuf,
    mode: u32,
    logical_len: u64,
    modified_secs: i64,
    modified_nanos: u32,
    data_extents: Vec<PrivateDataExtent>,
}

fn restore_sparse_file<F>(
    destination: &Path,
    logical_len: u64,
    data_extents: &[PrivateDataExtent],
    encryption_key: &[u8; 32],
    load_ciphertext: &mut F,
) -> Result<()>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    validate_file_extents(
        logical_len,
        data_extents
            .iter()
            .map(|extent| (extent.offset, extent.logical_len)),
    )?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    file.set_len(logical_len)?;
    for extent in data_extents {
        file.seek(SeekFrom::Start(extent.offset))?;
        let mut written = 0_u64;
        for reference in &extent.sectors {
            let plaintext = decrypt_reference(encryption_key, reference, load_ciphertext)?;
            file.write_all(&plaintext)?;
            written = written
                .checked_add(plaintext.len() as u64)
                .context("restored extent length overflow")?;
        }
        if written != extent.logical_len {
            bail!("restored extent length does not match signed metadata");
        }
    }
    file.sync_all()?;
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
