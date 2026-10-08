//! Mount-free export of authenticated withdrawn private formats.
//! Original catalogs and explicitly selected preserved anchors are read-only.

mod inventory;
mod local_inventory;
mod recovery;
mod remote;
pub use inventory::{
    LegacyRevisionInventory, LegacyRevisionInventoryEntry,
    inventory_withdrawn_revisions_from_catalog,
    inventory_withdrawn_revisions_from_catalog_over_network,
};
pub use local_inventory::{
    LegacyAnchorAreaLocation, LegacyCaptureOwnership, LegacyGitBlobPin, LegacyGitGraphObject,
    LegacyGitGraphRef, LegacyGitRegistration, LegacyGitWorktreeRegistration,
    LegacyGuardedAnchorPin, LegacyGuardedCapture, LegacyLocalSectorRecipe, LegacyLocalSectorSource,
    LegacyLocalStateInventory, LegacyPendingCapture, LegacyPendingFilePin, LegacyPendingGitGraph,
    LegacyPreservedRecord, LegacyRetainedAnchor, LegacyRootRegistration, LegacySourceBinding,
    LegacyStorageVolumeRegistration, LegacyVolumeOwnership,
};
pub use remote::{
    LegacyExportPeer, LegacyPeerInventoryCoverage, LegacyPeerSources,
    export_withdrawn_revision_from_catalog_over_network,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use mb_core::{
    KeyMaterial, SectorId, SignedRecord, UserRevision, V1_MAX_CATALOG_BYTES, V1_SECTOR_SIZE,
    canonical_bytes_bounded, decode_canonical, merkle_commit, sector_root,
};
use mb_store::PinnedDirectory;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::guarded_metadata::{
    GuardedGitPrivateMetadataV7, GuardedPrivateEntryV6, GuardedPrivateMetadataV6,
};
use crate::snapshot::{
    RecoveredGitBlobReader, checked_metadata_length, decrypt_reference, local_sector_for_export,
    recovered_inline_sector_for_export, restore_guarded_entries, validate_restore_revision,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyExportReport {
    pub format_version: u16,
    pub private_format: u16,
    pub revision_id: Uuid,
    pub protected_root_id: Uuid,
    pub revision_body_hash: String,
    pub namespace_entries: u64,
    pub information_sectors: u64,
    pub git_objects: Option<u32>,
}

fn require_export_parent_path(parent: &PinnedDirectory, path: &Path) -> Result<()> {
    const CHANGED: &str =
        "export destination parent changed during recovery; select another destination";
    let pinned = parent.as_file().metadata()?;
    let current = std::fs::metadata(path).context(CHANGED)?;
    ensure!(
        current.is_dir() && current.dev() == pinned.dev() && current.ino() == pinned.ino(),
        CHANGED
    );
    Ok(())
}

/// Export one owner/writer-signed legacy revision into a new package. Required
/// ciphertexts must be available and match every signed reference/commitment.
/// The package contains `namespace`, optional `history.git`, signed provenance
/// and a report. It is independent of native enrollment and is not permission
/// to retire the original installation, retained revisions or peer data.
pub fn export_withdrawn_revision_from_source<F>(
    keys: &KeyMaterial,
    revision: &SignedRecord<UserRevision>,
    target: &Path,
    load: F,
) -> Result<LegacyExportReport>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    export_withdrawn_revision_in_parent(keys, revision, target, None, load, || Ok(()))
}

fn export_withdrawn_revision_in_parent<F>(
    keys: &KeyMaterial,
    revision: &SignedRecord<UserRevision>,
    target: &Path,
    pinned_parent: Option<PinnedDirectory>,
    mut load: F,
    mut verify_inputs: impl FnMut() -> Result<()>,
) -> Result<LegacyExportReport>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    let metadata_length = checked_metadata_length(revision)?;
    let signed = canonical_bytes_bounded(revision, V1_MAX_CATALOG_BYTES)?;
    validate_restore_revision(keys, revision.value.guild_id, revision)?;
    let commitments = revision.value.sector_commitments.as_ref();
    let count = revision.value.metadata_sectors.len() + revision.value.data_sectors.len();
    ensure!(
        commitments.is_none_or(|values| values.len() == count),
        "revision commitment count differs from its sectors"
    );
    let mut references = BTreeMap::new();
    for (index, reference) in revision
        .value
        .metadata_sectors
        .iter()
        .chain(&revision.value.data_sectors)
        .enumerate()
    {
        ensure!(
            reference.logical_len > 0 && reference.logical_len as usize <= V1_SECTOR_SIZE,
            "invalid legacy sector geometry"
        );
        let pair = (reference, commitments.map(|values| &values[index]));
        if let Some(previous) = references.insert(reference.id, pair) {
            ensure!(previous == pair, "conflicting signed sector references");
        }
    }
    let mut verified = |id: &SectorId| -> Result<Vec<u8>> {
        let (reference, commitment) = references
            .get(id)
            .context("private metadata references an unsigned sector")?;
        let bytes = load(id)?;
        ensure!(
            bytes.len() == V1_SECTOR_SIZE && sector_root(&bytes) == reference.root,
            "legacy export sector failed its signed root"
        );
        if let Some(commitment) = commitment {
            ensure!(
                merkle_commit(&bytes)? == **commitment,
                "legacy export sector failed its signed commitment"
            );
        }
        Ok(bytes)
    };
    let encryption_key = keys.guild_data_key(&revision.value.guild_id);
    let mut encoded = Vec::with_capacity(metadata_length);
    for reference in &revision.value.metadata_sectors {
        encoded.extend(decrypt_reference(
            &encryption_key,
            reference,
            &mut verified,
        )?);
    }
    let format: u16 = postcard::take_from_bytes(&encoded)?.0;
    let (namespace, git) = match format {
        6 => (GuardedPrivateMetadataV6::decode(&encoded)?, None),
        7 => {
            let metadata =
                GuardedGitPrivateMetadataV7::decode(&encoded, revision.value.protected_root_id)?;
            (metadata.guarded, Some(metadata.git))
        }
        _ => bail!("legacy export requires withdrawn private metadata format 6 or 7"),
    };
    let data: BTreeMap<_, _> = revision
        .value
        .data_sectors
        .iter()
        .map(|reference| (reference.id, reference))
        .collect();
    let mut used = BTreeSet::new();
    let mut require_data = |reference: &mb_core::SectorRef| -> Result<()> {
        ensure!(
            data.get(&reference.id).copied() == Some(reference),
            "private extent differs from its signed data sector"
        );
        used.insert(reference.id);
        Ok(())
    };
    for entry in &namespace.entries {
        if let GuardedPrivateEntryV6::File { data_extents, .. } = entry {
            for extent in data_extents {
                for reference in &extent.sectors {
                    require_data(reference)?;
                }
            }
        }
    }
    if let Some(git) = &git {
        for blob in &git.blobs {
            for extent in &blob.data_extents {
                for reference in &extent.sectors {
                    require_data(reference)?;
                }
            }
        }
    }
    ensure!(
        used.len() == data.len(),
        "signed data sectors are missing from the legacy namespace/history"
    );
    // Complete availability/root preflight before creating any output. Reads
    // during construction are independently verified again in case inputs change.
    for id in references.keys() {
        verified(id)?;
    }
    let parent_path = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = target
        .file_name()
        .context("export target needs a file name")?;
    let parent = match pinned_parent {
        Some(parent) => parent,
        None => PinnedDirectory::open(parent_path)?,
    };
    require_export_parent_path(&parent, parent_path)?;
    ensure!(
        parent.entry_identity(name, true)?.is_none(),
        "export target already exists"
    );
    verify_inputs()?;
    let staging_name = format!(".mutualbackup-legacy-export-{}", Uuid::new_v4());
    let staging = parent.create_child_directory(&staging_name)?;
    let identity = staging.identity()?;
    let result = (|| {
        let tree = staging.create_child_directory("namespace")?;
        restore_guarded_entries(&tree, &namespace, &encryption_key, &mut verified, true)?;
        let git_objects = if let Some(descriptor) = &git {
            let history = staging.create_child_directory("history.git")?;
            git2::Repository::init_bare(history.descriptor_path())?;
            let count = descriptor.export_to_bare(&history.descriptor_path(), |blob, output| {
                let mut reader = RecoveredGitBlobReader::new(blob, &encryption_key, &mut verified);
                std::io::copy(&mut reader, output).map(|_| ())
            })?;
            // Stock Git owns this output. Flush its bounded directory traversal
            // before the package's single no-replace publication.
            for entry in walkdir::WalkDir::new(history.descriptor_path().canonicalize()?)
                .max_open(1)
                .contents_first(true)
                .follow_links(false)
            {
                let entry = entry?;
                ensure!(
                    entry.file_type().is_file() || entry.file_type().is_dir(),
                    "unexpected Git export object type"
                );
                File::open(entry.path())?.sync_all()?;
            }
            Some(count)
        } else {
            None
        };
        let report = LegacyExportReport {
            format_version: 1,
            private_format: format,
            revision_id: revision.value.revision_id,
            protected_root_id: revision.value.protected_root_id,
            revision_body_hash: hex::encode(revision.value.hash()?),
            namespace_entries: namespace.entries.len() as u64,
            information_sectors: references.len() as u64,
            git_objects,
        };
        let mut provenance = staging.create_child_file("signed-revision.postcard")?;
        provenance.write_all(&signed)?;
        provenance.sync_all()?;
        let mut manifest = staging.create_child_file("export.json")?;
        serde_json::to_writer_pretty(&mut manifest, &report)?;
        manifest.write_all(b"\n")?;
        manifest.sync_all()?;
        staging.sync_all()?;
        verify_inputs()?;
        require_export_parent_path(&parent, parent_path)?;
        parent.rename_child_no_replace(&staging_name, name)?;
        ensure!(
            parent.entry_identity(name, true)? == Some(identity),
            "export destination changed during publication"
        );
        parent.sync_all()?;
        Ok(report)
    })();
    if result.is_err() && parent.entry_identity(&staging_name, true)? == Some(identity) {
        if let Err(cleanup) = parent.remove_child_directory(&staging_name, identity) {
            return result.with_context(|| {
                format!(
                    "unfinished export {} could not be removed: {cleanup}",
                    parent_path.join(&staging_name).display()
                )
            });
        }
        parent.sync_all()?;
    }
    result
}

/// Read an owner-signed Postcard revision and exact 64 KiB ciphertext files
/// named `<sector-id-hex>.bin`. No daemon, control database or mount is opened.
pub fn export_withdrawn_revision_from_files(
    keys: &KeyMaterial,
    revision_file: &Path,
    sector_directory: &Path,
    target: &Path,
) -> Result<LegacyExportReport> {
    let input = revision_file.canonicalize()?;
    let sector_path = sector_directory.canonicalize()?;
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?;
    ensure!(
        !parent.starts_with(&sector_path)
            && !parent.starts_with(input.parent().context("revision input has no parent")?),
        "export destination must be outside revision and ciphertext input directories"
    );
    let pinned_parent = remote::export_file_parent_preflight(
        &parent,
        input.parent().context("revision input has no parent")?,
        &sector_path,
    )?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(revision_file)?;
    ensure!(
        file.metadata()?.is_file(),
        "revision input must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(V1_MAX_CATALOG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= V1_MAX_CATALOG_BYTES,
        "revision input exceeds its bounded legacy format"
    );
    let revision: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
    ensure!(
        canonical_bytes_bounded(&revision, V1_MAX_CATALOG_BYTES)? == bytes,
        "revision input is not canonical Postcard"
    );
    let sectors = PinnedDirectory::open(&sector_path)?;
    export_withdrawn_revision_in_parent(
        keys,
        &revision,
        target,
        Some(pinned_parent),
        |id| {
            let file = sectors
                .open_child_file(format!("{}.bin", hex::encode(id)))?
                .context("required legacy ciphertext is unavailable")?;
            ensure!(
                file.metadata()?.len() == V1_SECTOR_SIZE as u64,
                "legacy ciphertext file must contain exactly one sector"
            );
            let mut bytes = Vec::with_capacity(V1_SECTOR_SIZE);
            file.take(V1_SECTOR_SIZE as u64 + 1)
                .read_to_end(&mut bytes)?;
            Ok(bytes)
        },
        || Ok(()),
    )
}

/// Export available recovered ciphertext directly from an existing installation
/// inspected read-only. No key wrapping, migration, journal replay, source-hint
/// update, native-anchor/view access or recovery-cache retirement is performed.
pub fn export_withdrawn_revision_from_catalog(
    keys: &KeyMaterial,
    data_dir: &Path,
    revision_id: Uuid,
    target: &Path,
) -> Result<LegacyExportReport> {
    export_withdrawn_revision_from_catalog_with_anchor_areas(
        keys,
        data_dir,
        revision_id,
        target,
        &[],
    )
}

/// Explicitly selected preserved areas may supply authenticated anchor ranges.
/// Locator path hints and recorded filesystem IDs are not used to discover or
/// reopen the original view; relocated copies are checked against signed roots.
pub fn export_withdrawn_revision_from_catalog_with_anchor_areas(
    keys: &KeyMaterial,
    data_dir: &Path,
    revision_id: Uuid,
    target: &Path,
    anchor_areas: &[std::path::PathBuf],
) -> Result<LegacyExportReport> {
    export_withdrawn_revision_from_catalog_with_preserved_sources(
        keys,
        data_dir,
        revision_id,
        target,
        anchor_areas,
        &[],
    )
}

/// Explicit preserved sources are inspected without daemon startup or mutation.
pub fn export_withdrawn_revision_from_catalog_with_preserved_sources(
    keys: &KeyMaterial,
    data_dir: &Path,
    revision_id: Uuid,
    target: &Path,
    anchor_areas: &[std::path::PathBuf],
    parity_volumes: &[std::path::PathBuf],
) -> Result<LegacyExportReport> {
    export_catalog(
        keys,
        data_dir,
        revision_id,
        target,
        anchor_areas,
        parity_volumes,
        None,
    )
}

fn export_catalog(
    keys: &KeyMaterial,
    data_dir: &Path,
    revision_id: Uuid,
    target: &Path,
    anchor_areas: &[std::path::PathBuf],
    parity_volumes: &[std::path::PathBuf],
    remote: Option<&remote::PeerRecovery>,
) -> Result<LegacyExportReport> {
    let data_dir = data_dir.canonicalize()?;
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?;
    ensure!(
        !parent.starts_with(&data_dir),
        "export destination must be outside the original installation"
    );
    let protected_inputs: Vec<_> = anchor_areas.iter().chain(parity_volumes).cloned().collect();
    let pinned_parent =
        remote::export_parent_preflight(keys, &data_dir, &parent, &protected_inputs)?;
    let (control, guard) = crate::volume::open_preserved_control_store(&data_dir, keys)?;
    let mut selected = control.with_read_only_snapshot(|| {
        let mut selected = control
            .get_record_bounded(
                "user-revision",
                revision_id.as_bytes(),
                V1_MAX_CATALOG_BYTES,
            )?
            .map(|bytes| decode_canonical::<SignedRecord<UserRevision>>(&bytes))
            .transpose()?;
        if selected.is_none() {
            control.for_each_record_bounded(
                "user-revision-head",
                48,
                V1_MAX_CATALOG_BYTES,
                |key, bytes| {
                    let revision: SignedRecord<UserRevision> = decode_canonical(bytes)?;
                    if revision.value.revision_id != revision_id
                        || revision.value.owner != keys.node_id()
                    {
                        return Ok(true);
                    }
                    let mut scoped = revision.value.guild_id.to_vec();
                    scoped.extend(revision.value.protected_root_id.as_bytes());
                    ensure!(
                        key == scoped || key == revision.value.guild_id,
                        "legacy revision head has a conflicting scope"
                    );
                    selected = Some(revision);
                    Ok(false)
                },
            )?;
        }
        if selected.is_none() {
            control.for_each_record_bounded(
                "guild-checkpoint",
                32,
                V1_MAX_CATALOG_BYTES,
                |key, bytes| {
                    let checkpoint: mb_core::QuorumCheckpoint = decode_canonical(bytes)?;
                    let Some(revision) = checkpoint.checkpoint.revisions.iter().find(|revision| {
                        revision.value.revision_id == revision_id
                            && revision.value.owner == keys.node_id()
                    }) else {
                        return Ok(true);
                    };
                    ensure!(
                        canonical_bytes_bounded(&checkpoint, V1_MAX_CATALOG_BYTES)? == bytes,
                        "legacy checkpoint is not canonical"
                    );
                    checkpoint.verify()?;
                    ensure!(
                        key == checkpoint.hash()?,
                        "legacy checkpoint record has a conflicting hash"
                    );
                    selected = Some(revision.clone());
                    Ok(false)
                },
            )?;
        }
        Ok(selected)
    })?;
    let mut downloaded_checkpoint = None;
    if selected.is_none()
        && let Some(remote) = remote
        && let Some(checkpoint) = remote.find_revision(&control, keys.node_id(), revision_id)?
    {
        selected = checkpoint
            .checkpoint
            .revisions
            .iter()
            .find(|revision| {
                revision.value.revision_id == revision_id && revision.value.owner == keys.node_id()
            })
            .cloned();
        downloaded_checkpoint = Some(checkpoint);
    }
    let revision =
        selected.context("requested signed revision is unavailable in the preserved catalog")?;
    ensure!(
        revision.value.revision_id == revision_id,
        "legacy revision record has a conflicting ID"
    );
    checked_metadata_length(&revision)?;
    canonical_bytes_bounded(&revision, V1_MAX_CATALOG_BYTES)?;
    validate_restore_revision(keys, revision.value.guild_id, &revision)?;
    let mut areas = Vec::new();
    let mut area_ids = BTreeSet::new();
    for path in anchor_areas {
        let area = mb_store::PreservedAnchorArea::open(path)
            .with_context(|| format!("open preserved anchor area {}", path.display()))?;
        ensure!(
            !parent.starts_with(path.canonicalize()?),
            "export destination must be outside preserved anchor areas"
        );
        ensure!(
            area_ids.insert(area.area_id()),
            "preserved anchor area ID supplied more than once"
        );
        areas.push(area);
    }
    let mut volumes = Vec::new();
    let mut volume_ids = BTreeSet::new();
    for path in parity_volumes {
        ensure!(
            !parent.starts_with(path.canonicalize()?),
            "export destination must be outside preserved parity volumes"
        );
        let volume = crate::PreservedParityVolume::open(path, keys)
            .with_context(|| format!("open preserved parity volume {}", path.display()))?;
        ensure!(
            volume_ids.insert(volume.volume_id()),
            "preserved parity volume ID supplied more than once"
        );
        volumes.push(volume);
    }
    let references: BTreeMap<_, _> = revision
        .value
        .metadata_sectors
        .iter()
        .chain(&revision.value.data_sectors)
        .map(|reference| (reference.id, reference))
        .collect();
    let guild = revision.value.guild_id;
    let load_local = |reference: &mb_core::SectorRef| {
        if areas.is_empty() {
            recovered_inline_sector_for_export(&control, keys, guild, reference)
        } else {
            local_sector_for_export(&control, keys, guild, reference, &areas)
        }
    };
    let mut missing = BTreeSet::new();
    for reference in references.values() {
        if !load_local(reference).is_ok_and(|bytes| bytes.is_some()) {
            missing.insert(reference.root);
        }
    }
    let mut recovered = BTreeMap::new();
    if !missing.is_empty() {
        // One bounded-memory locator scan, then indexed payload lookups.
        // Only requested roots are retained. A corrupt duplicate cannot hide
        // another exact, authenticated copy in the recovery cache.
        control.for_each_recovery_shard_locator(&guild, |locator| {
            if missing.contains(&locator.root)
                && !recovered.contains_key(&locator.root)
                && control
                    .recovery_shard(
                        &locator.checkpoint_hash,
                        &guild,
                        &locator.group_id,
                        locator.shard_index,
                        &locator.root,
                    )
                    .is_ok()
            {
                recovered.insert(locator.root, locator);
            }
            Ok(())
        })?;
    }
    let mut checkpoint_recovery =
        recovery::CheckpointRecovery::with_checkpoint(downloaded_checkpoint)?;
    let inputs = recovery::RecoveryInputs {
        control_guard: &guard,
        volumes: &volumes,
        remote,
    };
    export_withdrawn_revision_in_parent(
        keys,
        &revision,
        target,
        Some(pinned_parent),
        |id| {
            let reference = references
                .get(id)
                .context("unsigned legacy sector requested")?;
            let local_error = match load_local(reference) {
                Ok(Some(bytes)) => return Ok(bytes),
                Ok(None) => None,
                Err(error) => Some(error),
            };
            let Some(locator) = recovered.get(&reference.root) else {
                let checkpoint_error =
                    match checkpoint_recovery.load(&control, &revision, reference, &inputs) {
                        Ok(Some(bytes)) => return Ok(bytes),
                        Ok(None) => None,
                        Err(error) => Some(error),
                    };
                if let Some(bytes) = remote.and_then(|peer| peer.sector(guild, reference)) {
                    return Ok(bytes);
                }
                if let Some(error) = checkpoint_error {
                    return Err(error);
                }
                if let Some(error) = local_error {
                    return Err(error).context("legacy source could not be authenticated; original anchors and journals remain preserved");
                }
                bail!(
                    "legacy sector has no available recovered Inline/cache ciphertext or authenticated preserved anchor range; original anchors and journals remain preserved"
                );
            };
            Ok(control.recovery_shard(
                &locator.checkpoint_hash,
                &guild,
                &locator.group_id,
                locator.shard_index,
                &locator.root,
            )?)
        },
        || {
            guard.verify_unchanged()?;
            for volume in &volumes {
                volume.verify_unchanged()?;
            }
            Ok(())
        },
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{GuardedPrivateStatV6, PrivateDataExtent};
    use ed25519_dalek::SigningKey;
    use mb_core::{
        SectorPurpose, SectorRef, Seed, USER_REVISION_DOMAIN, V1_CIPHER_PROFILE, canonical_bytes,
        encrypted_sector, make_sector_id,
    };
    use mb_git::{GitBackupBlob, GitBackupDescriptor, GitDataExtent, GitGraphObject, GitGraphRef};
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::{ffi::OsStringExt, fs::MetadataExt},
    };

    type Fixture = (
        KeyMaterial,
        SignedRecord<UserRevision>,
        BTreeMap<SectorId, Vec<u8>>,
    );

    fn fixture(format: u16) -> Fixture {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([49; 32]));
        let guild = [50; 32];
        let root = Uuid::from_bytes([51; 16]);
        let revision_id = Uuid::from_bytes([52; 16]);
        let encryption = keys.guild_data_key(&guild);
        let data_id = make_sector_id(keys.node_id(), revision_id, SectorPurpose::Data, 0);
        let (data, data_bytes) = encrypted_sector(&encryption, data_id, b"raw").unwrap();
        let stat = |mode| GuardedPrivateStatV6 {
            mode,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            atime_secs: 1_700_000_000,
            atime_nanos: 123,
            modified_secs: 1_700_000_001,
            modified_nanos: 456,
        };
        let namespace = GuardedPrivateMetadataV6 {
            format_version: 6,
            root: stat(0o750),
            entries: vec![
                GuardedPrivateEntryV6::Directory {
                    path: b"nested".to_vec(),
                    stat: stat(0o700),
                    logical_len: 4096,
                },
                GuardedPrivateEntryV6::File {
                    path: b"nested/\xfe".to_vec(),
                    stat: stat(0o640),
                    logical_len: 1024 * 1024,
                    link_group: 0,
                    data_extents: vec![PrivateDataExtent {
                        offset: 1000,
                        logical_len: 3,
                        sectors: vec![data.clone()],
                    }],
                },
                GuardedPrivateEntryV6::HardLink {
                    path: b"nested/\xff".to_vec(),
                    stat: stat(0o640),
                    logical_len: 1024 * 1024,
                    link_group: 0,
                },
            ],
        };
        let encoded = if format == 6 {
            canonical_bytes(&namespace).unwrap()
        } else {
            canonical_bytes(&GuardedGitPrivateMetadataV7 {
                format_version: 7,
                guarded: namespace,
                git: git_descriptor(root, data.clone()),
            })
            .unwrap()
        };
        let metadata_id = make_sector_id(keys.node_id(), revision_id, SectorPurpose::Metadata, 0);
        let (metadata, metadata_bytes) =
            encrypted_sector(&encryption, metadata_id, &encoded).unwrap();
        let writer = SigningKey::from_bytes(&[53; 32]);
        let mut body = UserRevision {
            format_version: 5,
            guild_id: guild,
            protected_root_id: root,
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id,
            owner: keys.node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors: vec![metadata],
            data_sectors: vec![data],
            sector_commitments: Some(vec![
                merkle_commit(&metadata_bytes).unwrap(),
                merkle_commit(&data_bytes).unwrap(),
            ]),
        };
        body.sign_writer(&writer).unwrap();
        let revision = SignedRecord::sign(USER_REVISION_DOMAIN, body, &keys).unwrap();
        (
            keys,
            revision,
            BTreeMap::from([(data_id, data_bytes), (metadata_id, metadata_bytes)]),
        )
    }

    fn git_descriptor(root: Uuid, sector: SectorRef) -> GitBackupDescriptor {
        use git2::{ObjectType, Oid};
        let blob = Oid::hash_object(ObjectType::Blob, b"raw").unwrap();
        let mut tree_bytes = b"100644 payload\0".to_vec();
        tree_bytes.extend(blob.as_bytes());
        let tree = Oid::hash_object(ObjectType::Tree, &tree_bytes).unwrap();
        let commit_bytes = format!("tree {tree}\nauthor Export <export@example.test> 1 +0000\ncommitter Export <export@example.test> 1 +0000\n\nlegacy\n").into_bytes();
        let commit = Oid::hash_object(ObjectType::Commit, &commit_bytes).unwrap();
        let tag_bytes = format!("object {commit}\ntype commit\ntag legacy\ntagger Export <export@example.test> 1 +0000\n\nretained\n").into_bytes();
        let tag = Oid::hash_object(ObjectType::Tag, &tag_bytes).unwrap();
        let oid = |id: Oid| <[u8; 20]>::try_from(id.as_bytes()).unwrap();
        let mut objects = vec![
            GitGraphObject {
                oid: oid(tree),
                kind: 2,
                bytes: tree_bytes,
            },
            GitGraphObject {
                oid: oid(commit),
                kind: 1,
                bytes: commit_bytes,
            },
            GitGraphObject {
                oid: oid(tag),
                kind: 3,
                bytes: tag_bytes,
            },
        ];
        objects.sort_by_key(|object| object.oid);
        let mut refs = vec![
            GitGraphRef {
                name: b"refs/heads/main".to_vec(),
                oid: oid(commit),
            },
            GitGraphRef {
                name: b"refs/heads/topic".to_vec(),
                oid: oid(commit),
            },
            GitGraphRef {
                name: b"refs/remotes/origin/main".to_vec(),
                oid: oid(commit),
            },
            GitGraphRef {
                name: b"refs/mutualbackup/pins/retained".to_vec(),
                oid: oid(commit),
            },
            GitGraphRef {
                name: b"refs/tags/legacy".to_vec(),
                oid: oid(tag),
            },
        ];
        refs.sort_by(|a, b| a.name.cmp(&b.name));
        let descriptor = GitBackupDescriptor {
            format_version: 4,
            repository_id: root,
            refs,
            objects,
            blobs: vec![GitBackupBlob {
                oid: oid(blob),
                logical_len: 3,
                data_extents: vec![GitDataExtent {
                    offset: 0,
                    logical_len: 3,
                    sectors: vec![sector],
                }],
            }],
            head_branch: "topic".into(),
        };
        descriptor.validate().unwrap();
        descriptor
    }

    pub(crate) fn split_packed_fixture(format: u16) -> (Fixture, mb_core::PackingResult) {
        let (keys, revision, ciphertexts) = fixture(format);
        let profile = mb_core::PackingProfile {
            format_version: 1,
            sector_size: V1_SECTOR_SIZE as u32,
            slot_size: 16 * 1024,
        };
        let inputs = revision
            .value
            .metadata_sectors
            .iter()
            .chain(&revision.value.data_sectors)
            .enumerate()
            .map(|(index, reference)| mb_core::PackingInput {
                owner: keys.node_id(),
                protected_root: mb_core::packing_protected_root(revision.value.protected_root_id),
                object_id: reference.id,
                source_commitment: Some(
                    revision.value.sector_commitments.as_ref().unwrap()[index].clone(),
                ),
                bytes: ciphertexts[&reference.id].clone(),
            })
            .collect();
        let mut packing = mb_core::pack_incremental(profile, None, inputs).unwrap();
        // Split both signed objects across the packed sectors.
        let mut slots: Vec<_> = packing
            .catalog
            .sectors
            .iter()
            .flat_map(|sector| sector.slots.clone())
            .filter(|slot| slot.source().is_some())
            .collect();
        slots.sort_by_key(|slot| {
            let source = slot.source().unwrap();
            (source.id.chunk_index, source.id.object_id)
        });
        let slots_per_sector = (profile.sector_size / profile.slot_size) as usize;
        packing.sectors.truncate(slots.len() / slots_per_sector);
        packing.catalog.sectors.truncate(packing.sectors.len());
        for (index, sector) in packing.sectors.iter_mut().enumerate() {
            sector.descriptor.slots =
                slots[index * slots_per_sector..(index + 1) * slots_per_sector].to_vec();
            sector.bytes.clear();
            for slot in &sector.descriptor.slots {
                let source = slot.source().unwrap();
                let start = source.source_offset as usize;
                sector.bytes.extend_from_slice(
                    &ciphertexts[&source.id.object_id][start..start + source.logical_len as usize],
                );
            }
            sector.descriptor.commitment = merkle_commit(&sector.bytes).unwrap();
            sector.descriptor.flat_root = if packing.catalog.format_version >= 3 {
                sector.descriptor.commitment.root
            } else {
                sector_root(&sector.bytes)
            };
            sector.descriptor.id = sector.descriptor.calculate_id(profile).unwrap();
            packing.catalog.sectors[index] = sector.descriptor.clone();
        }
        packing.catalog.id = packing.catalog.calculate_id().unwrap();
        packing.catalog.validate().unwrap();
        ((keys, revision, ciphertexts), packing)
    }

    #[test]
    fn legacy_export_unpacks_certified_cached_and_volume_sectors_with_split_object_chunks() {
        for format in [6, 7] {
            let ((keys, revision, _), packing) = split_packed_fixture(format);
            let mut checkpoint = mb_core::QuorumCheckpoint {
                checkpoint: mb_core::GuildCheckpoint {
                    format_version: 7,
                    guild_id: revision.value.guild_id,
                    genesis_hash: [99; 32],
                    generation: 1,
                    parent: None,
                    members: vec![mb_core::Member {
                        node_id: keys.node_id(),
                        recovery_public_key: keys.recovery_public_key(),
                        failure_domain: "fixture".into(),
                    }],
                    writer_fences: vec![mb_core::WriterFence {
                        owner: keys.node_id(),
                        epoch: 1,
                        public_key: revision.value.writer_public_key,
                    }],
                    revision_tombstones: vec![],
                    revisions: vec![revision.clone()],
                    coding_groups: vec![],
                    authority: Some(mb_core::CheckpointAuthority {
                        format_version: 1,
                        membership_epoch: 1,
                        quorum: mb_core::QuorumPolicy {
                            format_version: 1,
                            rule: mb_core::QuorumRule::Unanimous,
                        },
                    }),
                    packing_catalog: Some(packing.catalog),
                },
                signatures: vec![],
            };
            checkpoint.add_signature(&keys).unwrap();
            checkpoint.verify().unwrap();
            for case in 0..23 {
                let temp = tempfile::tempdir().unwrap();
                let data = temp.path().join("original");
                fs::create_dir(&data).unwrap();
                let store = mb_store::ControlStore::open(data.join("control.db"), &keys).unwrap();
                let mut certificate = checkpoint.clone();
                if case == 6 {
                    certificate.signatures[0].signature[0] ^= 1;
                }
                store
                    .put_record(
                        "guild-checkpoint",
                        &checkpoint.hash().unwrap(),
                        &canonical_bytes(&certificate).unwrap(),
                    )
                    .unwrap();
                store
                    .put_record("guarded-view-mount-v1", b"legacy", b"must-not-replay")
                    .unwrap();
                let volume = temp.path().join("preserved-volume");
                if case >= 7 {
                    fs::create_dir(&volume).unwrap();
                    preserve_variable_export_inputs(
                        &store,
                        &keys,
                        &checkpoint,
                        &packing.sectors,
                        &volume,
                        case,
                    );
                }
                for (index, sector) in packing.sectors.iter().enumerate() {
                    if (case == 1 && index == 0) || (case >= 7 && case != 22) {
                        continue;
                    }
                    let mut record = crate::node::PackedSectorRecord {
                        format_version: 1,
                        guild_id: revision.value.guild_id,
                        sector: sector.clone(),
                    };
                    if index == 0 {
                        match case {
                            2 => record.sector.bytes[0] ^= 1,
                            3 => record.guild_id = [98; 32],
                            4 => record.sector.descriptor.id = [97; 32],
                            5 => record.sector.bytes = vec![0; 1024 * 1024],
                            _ => {}
                        }
                    }
                    if case == 22 {
                        record.sector.bytes[0] ^= 1;
                    }
                    let key: Vec<_> = revision
                        .value
                        .guild_id
                        .iter()
                        .chain(&sector.descriptor.id)
                        .copied()
                        .collect();
                    store
                        .put_record("packed-sector", &key, &canonical_bytes(&record).unwrap())
                        .unwrap();
                }
                drop(store);
                let original = fs::read(data.join("control.db")).unwrap();
                let volume_before = fs::read(volume.join("parity.db")).ok();
                let target = if case == 19 {
                    volume.join("export")
                } else {
                    temp.path().join("export")
                };
                let mut volume_paths = if case >= 7 {
                    vec![volume.clone()]
                } else {
                    vec![]
                };
                if case == 18 {
                    volume_paths.push(volume.clone());
                }
                let result = export_withdrawn_revision_from_catalog_with_preserved_sources(
                    &keys,
                    &data,
                    revision.value.revision_id,
                    &target,
                    &[],
                    &volume_paths,
                );
                if case == 0 || (7..13).contains(&case) || (20..23).contains(&case) {
                    let report = result.unwrap();
                    assert_eq!(report.private_format, format);
                    assert_eq!(
                        &fs::read(
                            target
                                .join("namespace")
                                .join(std::ffi::OsString::from_vec(b"nested/\xfe".to_vec()))
                        )
                        .unwrap()[1000..1003],
                        b"raw"
                    );
                    if format == 7 {
                        assert!(git2::Repository::open_bare(target.join("history.git")).is_ok());
                    }
                } else {
                    assert!(result.is_err(), "accepted case {case}");
                    assert!(!target.exists());
                }
                assert_eq!(fs::read(data.join("control.db")).unwrap(), original);
                assert_eq!(fs::read(volume.join("parity.db")).ok(), volume_before);
                assert!(!volume.join(".mutualbackup-volume").exists());
                assert!(!data.join("control.key").exists());
            }
        }
    }

    fn preserve_variable_export_inputs(
        store: &mb_store::ControlStore,
        owner: &KeyMaterial,
        checkpoint: &mb_core::QuorumCheckpoint,
        sectors: &[mb_core::PackedSector],
        volume: &Path,
        case: usize,
    ) {
        use mb_core::{
            CODING_ATTEMPT_PLAN_DOMAIN, CodingAttemptPlan, CodingPlanGeometry, InformationRoleV2,
            ParityPlacementV2, RangeSectorRef,
        };
        let identities: Vec<_> = [49, 71, 72, 73]
            .into_iter()
            .map(|marker| KeyMaterial::from_seed(&Seed::from_bytes([marker; 32])))
            .collect();
        let id = Uuid::from_bytes(
            blake3::hash(&owner.node_id().0).as_bytes()[..16]
                .try_into()
                .unwrap(),
        );
        let mut parity =
            mb_store::ParityStore::open(volume.join("parity.db"), id.as_bytes(), owner).unwrap();
        let subsets = [[0, 1], [0, 2], [0, 3], [1, 2], [1, 3], [2, 3]];
        for (ordinal, sector) in sectors.iter().enumerate() {
            let profile = mb_core::CodingProfile::new(2, 2, sector.bytes.len() as u32);
            let filler = if case == 20 {
                vec![0; sector.bytes.len()]
            } else {
                vec![88; sector.bytes.len()]
            };
            let shards = mb_core::encode(profile, vec![sector.bytes.clone(), filler]).unwrap();
            let plan = CodingAttemptPlan {
                format_version: 1,
                attempt_id: [ordinal as u8 + 1; 16],
                checkpoint_hash: checkpoint.hash().unwrap(),
                membership_epoch: 1,
                geometry: CodingPlanGeometry {
                    format_version: 1,
                    guild_id: checkpoint.checkpoint.guild_id,
                    profile,
                    information: shards[..2]
                        .iter()
                        .enumerate()
                        .map(|(index, bytes)| InformationRoleV2 {
                            owner: identities[index].node_id(),
                            failure_domain: format!("site-{index}"),
                            sector: RangeSectorRef {
                                id: if index == 0 {
                                    sector.descriptor.id
                                } else {
                                    [ordinal as u8 + 90; 32]
                                },
                                commitment: mb_core::merkle_commit(bytes).unwrap(),
                                logical_len: profile.shard_size,
                                virtual_zero: index == 1 && case == 20,
                            },
                        })
                        .collect(),
                    parity: (0..2)
                        .map(|row| ParityPlacementV2 {
                            holder: identities[row + 2].node_id(),
                            failure_domain: format!("site-{}", row + 2),
                            row: row as u16,
                        })
                        .collect(),
                },
                delegator: identities[0].node_id(),
                coding_coordinator: identities[1].node_id(),
                verification_coordinator: identities[3].node_id(),
                expires_at_unix_seconds: 2_000_000_000,
                information_roots: None,
            };
            let plan =
                SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, plan, &identities[0]).unwrap();
            let mut transcript =
                crate::node::tests::test_coding_transcript(plan, &shards, &identities);
            let group = transcript.value.manifest.value.group.clone();
            if case == 14 {
                transcript.signature[0] ^= 1;
            }
            if case != 21 {
                store
                    .put_record(
                        "coding-group-transcript",
                        &group.id,
                        &canonical_bytes(&transcript).unwrap(),
                    )
                    .unwrap();
            }
            let positions: &[usize] = match case {
                7..=12 => &subsets[case - 7],
                13 => &[3],
                20 => &[2],
                21 => &[0],
                _ => &[2, 3],
            };
            for &index in positions {
                let mut bytes = shards[index].clone();
                if case == 17 {
                    bytes[0] ^= 1;
                }
                let object = mb_store::VariableParityObject {
                    format_version: 2,
                    guild_id: if case == 16 { [98; 32] } else { group.guild_id },
                    group_id: if index < 2 {
                        transcript.value.plan.value.geometry.information[index]
                            .sector
                            .id
                    } else {
                        group.id
                    },
                    shard_index: index as u16,
                    commitment: mb_core::merkle_commit(&bytes).unwrap(),
                    bytes,
                };
                parity
                    .stage_attempt(
                        &[ordinal as u8 + 1; 16],
                        &object,
                        b"retained receipt",
                        16 * V1_SECTOR_SIZE as u64,
                    )
                    .unwrap();
                if case != 15 {
                    parity
                        .activate_attempt_object(
                            &[ordinal as u8 + 1; 16],
                            &object.group_id,
                            object.shard_index,
                            &object.commitment,
                            &[96; 32],
                        )
                        .unwrap();
                }
            }
        }
    }

    pub(crate) type FixedFixture = (
        Fixture,
        Vec<KeyMaterial>,
        Vec<(mb_core::CodingGroup, [Vec<u8>; 5])>,
        mb_core::QuorumCheckpoint,
    );

    pub(crate) fn fixed_checkpoint_fixture(format: u16) -> FixedFixture {
        use mb_core::{
            CodingGroup, GuildCheckpoint, InformationRole, Member, ParityRole, QuorumCheckpoint,
            ShardRole, WriterFence,
        };
        let (keys, revision, sectors) = fixture(format);
        let members: Vec<_> = [49, 71, 72, 73, 74]
            .into_iter()
            .map(|byte| KeyMaterial::from_seed(&Seed::from_bytes([byte; 32])))
            .collect();
        let mut roster: Vec<_> = members
            .iter()
            .enumerate()
            .map(|(index, keys)| Member {
                node_id: keys.node_id(),
                recovery_public_key: keys.recovery_public_key(),
                failure_domain: format!("domain-{index}"),
            })
            .collect();
        roster.sort_by_key(|member| member.node_id);
        let mut groups = Vec::new();
        for (index, reference) in revision
            .value
            .metadata_sectors
            .iter()
            .chain(&revision.value.data_sectors)
            .enumerate()
        {
            let shards = mb_core::encode_3_2([
                sectors[&reference.id].clone(),
                vec![index as u8 + 1; V1_SECTOR_SIZE],
                vec![index as u8 + 7; V1_SECTOR_SIZE],
            ])
            .unwrap();
            let mut group = CodingGroup {
                id: [0; 32],
                format_version: 1,
                guild_id: revision.value.guild_id,
                data_shards: 3,
                parity_shards: 2,
                shard_size: V1_SECTOR_SIZE as u32,
                roles: [
                    ShardRole::Information(InformationRole {
                        owner: keys.node_id(),
                        sector: reference.clone(),
                    }),
                    ShardRole::Information(InformationRole {
                        owner: members[1].node_id(),
                        sector: SectorRef {
                            id: [80 + index as u8; 32],
                            root: sector_root(&shards[1]),
                            logical_len: 0,
                        },
                    }),
                    ShardRole::Information(InformationRole {
                        owner: members[2].node_id(),
                        sector: SectorRef {
                            id: [90 + index as u8; 32],
                            root: sector_root(&shards[2]),
                            logical_len: 0,
                        },
                    }),
                    ShardRole::Parity(ParityRole {
                        holder: members[3].node_id(),
                        row: 0,
                        root: sector_root(&shards[3]),
                    }),
                    ShardRole::Parity(ParityRole {
                        holder: members[4].node_id(),
                        row: 1,
                        root: sector_root(&shards[4]),
                    }),
                ],
            };
            group.id = group.calculate_id().unwrap();
            groups.push((group, shards));
        }
        groups.sort_by_key(|(group, _)| group.id);
        let mut checkpoint = QuorumCheckpoint {
            checkpoint: GuildCheckpoint {
                format_version: 3,
                guild_id: revision.value.guild_id,
                genesis_hash: [99; 32],
                generation: 1,
                parent: None,
                members: roster,
                writer_fences: vec![WriterFence {
                    owner: keys.node_id(),
                    epoch: 1,
                    public_key: revision.value.writer_public_key,
                }],
                revision_tombstones: vec![],
                revisions: vec![revision.clone()],
                coding_groups: groups.iter().map(|(group, _)| group.clone()).collect(),
                authority: None,
                packing_catalog: None,
            },
            signatures: vec![],
        };
        for member in &members {
            checkpoint.add_signature(member).unwrap();
        }
        checkpoint.verify().unwrap();
        ((keys, revision, sectors), members, groups, checkpoint)
    }

    #[test]
    fn legacy_export_reconstructs_every_cached_three_of_five_codeword_without_mutation() {
        let ((keys, revision, sectors), members, groups, checkpoint) = fixed_checkpoint_fixture(6);
        let hash = checkpoint.hash().unwrap();
        let combinations = [
            [0, 1, 2],
            [0, 1, 3],
            [0, 1, 4],
            [0, 2, 3],
            [0, 2, 4],
            [0, 3, 4],
            [1, 2, 3],
            [1, 2, 4],
            [1, 3, 4],
            [2, 3, 4],
        ];
        for positions in combinations {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("original");
            fs::create_dir(&data).unwrap();
            let mut store = mb_store::ControlStore::open(data.join("control.db"), &keys).unwrap();
            store
                .put_record(
                    "guild-checkpoint",
                    &hash,
                    &canonical_bytes(&checkpoint).unwrap(),
                )
                .unwrap();
            store
                .put_record("guarded-view-mount-v1", b"legacy", b"must-not-replay")
                .unwrap();
            for (group, shards) in &groups {
                for index in positions {
                    store
                        .stage_recovery_shard(
                            &hash,
                            &group.guild_id,
                            &group.id,
                            index as u8,
                            &sector_root(&shards[index]),
                            &shards[index],
                        )
                        .unwrap();
                }
            }
            drop(store);
            let original = fs::read(data.join("control.db")).unwrap();
            let (inspected, input_guard) =
                crate::volume::open_preserved_control_store(&data, &keys).unwrap();
            let mut decoder = recovery::CheckpointRecovery::default();
            for reference in revision
                .value
                .metadata_sectors
                .iter()
                .chain(&revision.value.data_sectors)
            {
                assert_eq!(
                    decoder
                        .load(
                            &inspected,
                            &revision,
                            reference,
                            &recovery::RecoveryInputs {
                                control_guard: &input_guard,
                                volumes: &[],
                                remote: None,
                            }
                        )
                        .unwrap()
                        .unwrap(),
                    sectors[&reference.id],
                    "{positions:?}"
                );
            }
            drop(inspected);
            let target = temp.path().join("export");
            export_withdrawn_revision_from_catalog(
                &keys,
                &data,
                revision.value.revision_id,
                &target,
            )
            .unwrap();
            assert_eq!(
                &fs::read(
                    target
                        .join("namespace")
                        .join(std::ffi::OsString::from_vec(b"nested/\xfe".to_vec()))
                )
                .unwrap()[1000..1003],
                b"raw"
            );
            assert_eq!(fs::read(data.join("control.db")).unwrap(), original);
            assert!(!data.join("control.key").exists());
        }
        // An earlier certified copy with no cached inputs cannot hide a later
        // certified copy of the exact same signed revision that has a codeword.
        let mut alternate = checkpoint.clone();
        alternate.checkpoint.generation = 2;
        alternate.checkpoint.parent = Some(hash);
        for member in &members {
            alternate.add_signature(member).unwrap();
        }
        alternate.verify().unwrap();
        let alternate_hash = alternate.hash().unwrap();
        let available_hash = std::cmp::max(hash, alternate_hash);
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("original");
        fs::create_dir(&data).unwrap();
        let mut store = mb_store::ControlStore::open(data.join("control.db"), &keys).unwrap();
        for certificate in [&checkpoint, &alternate] {
            store
                .put_record(
                    "guild-checkpoint",
                    &certificate.hash().unwrap(),
                    &canonical_bytes(certificate).unwrap(),
                )
                .unwrap();
        }
        for (group, shards) in &groups {
            for index in [2, 3, 4] {
                store
                    .stage_recovery_shard(
                        &available_hash,
                        &group.guild_id,
                        &group.id,
                        index as u8,
                        &sector_root(&shards[index]),
                        &shards[index],
                    )
                    .unwrap();
            }
        }
        drop(store);
        let original = fs::read(data.join("control.db")).unwrap();
        export_withdrawn_revision_from_catalog(
            &keys,
            &data,
            revision.value.revision_id,
            &temp.path().join("alternate-export"),
        )
        .unwrap();
        assert_eq!(fs::read(data.join("control.db")).unwrap(), original);

        // Missing or foreign-scoped cache input never substitutes for the
        // certified checkpoint's positions. Quorum loss also fails closed.
        for case in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("original");
            fs::create_dir(&data).unwrap();
            let mut store = mb_store::ControlStore::open(data.join("control.db"), &keys).unwrap();
            let mut changed = checkpoint.clone();
            if case == 1 {
                changed.signatures.pop();
            }
            store
                .put_record(
                    "guild-checkpoint",
                    &hash,
                    &canonical_bytes(&changed).unwrap(),
                )
                .unwrap();
            for (group, shards) in &groups {
                for index in if case != 0 { vec![2, 3, 4] } else { vec![3, 4] } {
                    store
                        .stage_recovery_shard(
                            &if case == 3 { [98; 32] } else { hash },
                            &if case == 2 { [97; 32] } else { group.guild_id },
                            &group.id,
                            index as u8,
                            &sector_root(&shards[index]),
                            &shards[index],
                        )
                        .unwrap();
                }
            }
            if case == 4 {
                store
                    .database_shell_statement(
                        "UPDATE recovery_shards SET bytes = zeroblob(65536) WHERE shard_index = 2",
                        false,
                    )
                    .unwrap();
            }
            drop(store);
            let original = fs::read(data.join("control.db")).unwrap();
            let target = temp.path().join("rejected");
            assert!(
                export_withdrawn_revision_from_catalog(
                    &keys,
                    &data,
                    revision.value.revision_id,
                    &target
                )
                .is_err()
            );
            assert!(!target.exists());
            assert_eq!(fs::read(data.join("control.db")).unwrap(), original);
        }
    }

    #[test]
    fn legacy_export_explicit_anchors_preserve_relocated_raw_bytes_and_metadata() {
        #[derive(Serialize)]
        enum Source {
            AnchorFile {
                locator: mb_store::AnchorFileLocator,
                offset: u64,
            },
            Inline(Vec<u8>),
            StableAnchorFile {
                locator: mb_store::StableAnchorFileLocator,
                offset: u64,
            },
        }
        #[derive(Serialize)]
        struct Recipe {
            guild_id: [u8; 32],
            reference: mb_core::SectorRef,
            source: Source,
        }
        for format in [6, 7] {
            let (keys, revision, sectors) = fixture(format);
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("original");
            fs::create_dir(&data).unwrap();
            let store = mb_store::ControlStore::open(data.join("control.db"), &keys).unwrap();
            store
                .put_record(
                    "user-revision",
                    revision.value.revision_id.as_bytes(),
                    &canonical_bytes(&revision).unwrap(),
                )
                .unwrap();
            store
                .put_record("guarded-view-mount-v1", b"legacy", b"must-not-replay")
                .unwrap();
            let area_id = Uuid::new_v4();
            let anchor_id = Uuid::new_v4();
            let area = temp.path().join("relocated-area");
            let anchor = area.join(anchor_id.to_string());
            fs::create_dir_all(&anchor).unwrap();
            let marker = area.join(".mutualbackup-anchor-area-v1");
            fs::write(&marker, format!("mutualbackup-anchor-area-v1\n{area_id}\n")).unwrap();
            let relative = if format == 6 {
                std::path::PathBuf::from("payload")
            } else {
                std::path::PathBuf::from(std::ffi::OsString::from_vec(b"payload-\xfe".to_vec()))
            };
            let payload = anchor.join(&relative);
            fs::write(&payload, b"prefixraw").unwrap();
            for reference in &revision.value.metadata_sectors {
                let plaintext = decrypt_reference(
                    &keys.guild_data_key(&revision.value.guild_id),
                    reference,
                    &mut |id| Ok(sectors[id].clone()),
                )
                .unwrap();
                store
                    .put_record(
                        "local-sector",
                        &reference.id,
                        &canonical_bytes(&Recipe {
                            guild_id: revision.value.guild_id,
                            reference: reference.clone(),
                            source: Source::Inline(plaintext),
                        })
                        .unwrap(),
                    )
                    .unwrap();
            }
            let reference = revision.value.data_sectors[0].clone();
            let source = if format == 6 {
                Source::AnchorFile {
                    locator: mb_store::AnchorFileLocator {
                        area: mb_store::AnchorAreaLocator {
                            area_id,
                            path_hint: temp.path().join("absent-old-view"),
                        },
                        anchor_id,
                        relative_path: "payload".into(),
                    },
                    offset: 6,
                }
            } else {
                Source::StableAnchorFile {
                    locator: mb_store::StableAnchorFileLocator {
                        area: mb_store::StableAnchorAreaLocator {
                            area_id,
                            path_hint: temp.path().join("absent-old-view"),
                            filesystem_id: u64::MAX,
                            volume_root_hint: temp.path().join("absent-volume"),
                        },
                        anchor_id,
                        relative_path: relative,
                    },
                    offset: 6,
                }
            };
            store
                .put_record(
                    "local-sector",
                    &reference.id,
                    &canonical_bytes(&Recipe {
                        guild_id: revision.value.guild_id,
                        reference: reference.clone(),
                        source,
                    })
                    .unwrap(),
                )
                .unwrap();
            drop(store);
            for path in [&marker, &payload] {
                File::open(path)
                    .unwrap()
                    .set_times(std::fs::FileTimes::new().set_accessed(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000),
                    ))
                    .unwrap();
            }
            let before: Vec<_> = [&marker, &payload]
                .map(|path| fs::metadata(path).unwrap())
                .into();
            let original = fs::read(data.join("control.db")).unwrap();
            let target = temp.path().join("export");
            assert!(
                export_withdrawn_revision_from_catalog(
                    &keys,
                    &data,
                    revision.value.revision_id,
                    &target
                )
                .is_err()
            );
            assert!(!target.exists());
            let report = export_withdrawn_revision_from_catalog_with_anchor_areas(
                &keys,
                &data,
                revision.value.revision_id,
                &target,
                std::slice::from_ref(&area),
            )
            .unwrap();
            assert_eq!(report.private_format, format);
            let content = fs::read(
                target
                    .join("namespace")
                    .join(std::ffi::OsString::from_vec(b"nested/\xfe".to_vec())),
            )
            .unwrap();
            assert_eq!(&content[1000..1003], b"raw");
            for (path, before) in [&marker, &payload].into_iter().zip(before) {
                let after = fs::metadata(path).unwrap();
                assert_eq!(
                    (
                        after.ino(),
                        after.len(),
                        after.atime(),
                        after.atime_nsec(),
                        after.mtime(),
                        after.mtime_nsec(),
                        after.ctime(),
                        after.ctime_nsec()
                    ),
                    (
                        before.ino(),
                        before.len(),
                        before.atime(),
                        before.atime_nsec(),
                        before.mtime(),
                        before.mtime_nsec(),
                        before.ctime(),
                        before.ctime_nsec()
                    )
                );
            }
            assert_eq!(fs::read(data.join("control.db")).unwrap(), original);
            assert!(!data.join("control.key").exists());
            assert!(
                export_withdrawn_revision_from_catalog_with_anchor_areas(
                    &keys,
                    &data,
                    revision.value.revision_id,
                    &area.join("unsafe-export"),
                    std::slice::from_ref(&area)
                )
                .is_err()
            );
            assert!(!area.join("unsafe-export").exists());
            // A damaged original is never exported merely because its locator exists.
            fs::write(&payload, b"prefixbad").unwrap();
            let rejected = temp.path().join("rejected");
            assert!(
                export_withdrawn_revision_from_catalog_with_anchor_areas(
                    &keys,
                    &data,
                    revision.value.revision_id,
                    &rejected,
                    &[area]
                )
                .is_err()
            );
            assert!(!rejected.exists());
        }
    }

    #[test]
    fn legacy_export_catalog_sources_preserve_database_keys_and_journals() {
        for mode in 0..4 {
            for journal_state in 0..3 {
                let (keys, revision, sectors) = fixture(if mode == 3 { 7 } else { 6 });
                let temp = tempfile::tempdir().unwrap();
                let data = temp.path().join("original");
                fs::create_dir(&data).unwrap();
                let mut store = if mode == 0 {
                    mb_store::ControlStore::open(data.join("control.db"), &keys).unwrap()
                } else {
                    crate::volume::open_control_store(&data, &keys).unwrap().0
                };
                store
                    .database_shell_statement("PRAGMA wal_autocheckpoint=0", false)
                    .unwrap();
                let signed = canonical_bytes(&revision).unwrap();
                match mode {
                    0 => store
                        .put_record(
                            "user-revision",
                            revision.value.revision_id.as_bytes(),
                            &signed,
                        )
                        .unwrap(),
                    1 | 2 => {
                        let mut key = revision.value.guild_id.to_vec();
                        if mode == 2 {
                            key.extend(revision.value.protected_root_id.as_bytes());
                        }
                        store
                            .put_record("user-revision-head", &key, &signed)
                            .unwrap();
                    }
                    _ => {
                        let mut checkpoint = mb_core::QuorumCheckpoint {
                            checkpoint: mb_core::GuildCheckpoint {
                                format_version: 4,
                                guild_id: revision.value.guild_id,
                                genesis_hash: [99; 32],
                                generation: 1,
                                parent: None,
                                members: vec![mb_core::Member {
                                    node_id: keys.node_id(),
                                    recovery_public_key: keys.recovery_public_key(),
                                    failure_domain: "fixture".into(),
                                }],
                                writer_fences: vec![mb_core::WriterFence {
                                    owner: keys.node_id(),
                                    epoch: 1,
                                    public_key: revision.value.writer_public_key,
                                }],
                                revision_tombstones: vec![],
                                revisions: vec![revision.clone()],
                                coding_groups: vec![],
                                authority: None,
                                packing_catalog: None,
                            },
                            signatures: vec![],
                        };
                        checkpoint.add_signature(&keys).unwrap();
                        checkpoint.verify().unwrap();
                        store
                            .put_record(
                                "guild-checkpoint",
                                &checkpoint.hash().unwrap(),
                                &canonical_bytes(&checkpoint).unwrap(),
                            )
                            .unwrap();
                    }
                }
                store
                    .put_record("guarded-view-mount-v1", b"legacy", b"must-not-replay")
                    .unwrap();
                for (index, reference) in revision
                    .value
                    .metadata_sectors
                    .iter()
                    .chain(&revision.value.data_sectors)
                    .enumerate()
                {
                    if mode < 2 || index == 0 {
                        let plaintext = decrypt_reference(
                            &keys.guild_data_key(&revision.value.guild_id),
                            reference,
                            &mut |id| Ok(sectors[id].clone()),
                        )
                        .unwrap();
                        crate::snapshot::install_inline_recipe(
                            &mut store,
                            revision.value.guild_id,
                            reference.clone(),
                            plaintext,
                        )
                        .unwrap();
                    } else {
                        store
                            .stage_recovery_shard(
                                &[61; 32],
                                &revision.value.guild_id,
                                &[index as u8; 32],
                                0,
                                &reference.root,
                                &sectors[&reference.id],
                            )
                            .unwrap();
                    }
                }
                // Extraction must not perform even an otherwise valid schema migration.
                store
                    .database_shell_statement(
                        "DROP INDEX protocol_records_paged_sector_sources",
                        false,
                    )
                    .unwrap();
                store
                    .database_shell_statement(
                        "UPDATE meta SET value = X'00000008' WHERE key = 'schema_version'",
                        false,
                    )
                    .unwrap();
                let data = if journal_state == 1 {
                    let copy = temp.path().join("preserved");
                    fs::create_dir(&copy).unwrap();
                    for name in ["control.db", "control.db-wal", "control.key"] {
                        if data.join(name).exists() {
                            fs::copy(data.join(name), copy.join(name)).unwrap();
                        }
                    }
                    copy
                } else {
                    data
                };
                let _writer = if journal_state == 2 {
                    Some(store)
                } else {
                    drop(store);
                    None
                };
                let files = || -> BTreeMap<_, _> {
                    fs::read_dir(&data)
                        .unwrap()
                        .map(|entry| {
                            let entry = entry.unwrap();
                            let bytes = fs::read(entry.path()).unwrap();
                            let digest = (entry.file_name() != "control.db-shm")
                                .then(|| blake3::hash(&bytes));
                            (entry.file_name(), (bytes.len(), digest))
                        })
                        .collect()
                };
                let original_files = files();
                let db = fs::read(data.join("control.db")).unwrap();
                let envelope = fs::read(data.join("control.key")).ok();
                let target = temp.path().join("export");
                let report = export_withdrawn_revision_from_catalog(
                    &keys,
                    &data,
                    revision.value.revision_id,
                    &target,
                )
                .unwrap();
                assert_eq!(report.private_format, if mode == 3 { 7 } else { 6 });
                let content = fs::read(
                    target
                        .join("namespace")
                        .join(std::ffi::OsString::from_vec(b"nested/\xfe".to_vec())),
                )
                .unwrap();
                assert_eq!(content.len(), 1024 * 1024);
                assert_eq!(&content[1000..1003], b"raw");
                assert_eq!(
                    fs::read(target.join("signed-revision.postcard")).unwrap(),
                    signed
                );
                assert_eq!(fs::read(data.join("control.db")).unwrap(), db);
                assert_eq!(fs::read(data.join("control.key")).ok(), envelope);
                crate::volume::with_inspected_control_snapshot(&data, &keys, |inspected| {
                    assert_eq!(
                        inspected
                            .get_record("guarded-view-mount-v1", b"legacy")
                            .unwrap()
                            .unwrap(),
                        b"must-not-replay"
                    );
                    for reference in revision
                        .value
                        .metadata_sectors
                        .iter()
                        .chain(&revision.value.data_sectors)
                    {
                        assert!(
                            recovered_inline_sector_for_export(
                                inspected,
                                &keys,
                                revision.value.guild_id,
                                reference
                            )
                            .unwrap()
                            .is_some()
                                || mode >= 2
                        );
                    }
                    Ok(())
                })
                .unwrap();
                assert_eq!(
                    files(),
                    original_files,
                    "mode {mode}, journal state {journal_state}"
                );
                assert!(
                    export_withdrawn_revision_from_catalog(
                        &keys,
                        &data,
                        revision.value.revision_id,
                        &data.join("unsafe-export")
                    )
                    .is_err()
                );
                assert!(!data.join("unsafe-export").exists());
            }
        }
    }

    #[test]
    fn legacy_export_input_changes_before_staging_or_publication_never_publish() {
        for during_construction in [false, true] {
            let (keys, revision, sectors) = fixture(7);
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("original");
            fs::create_dir(&data).unwrap();
            let path = data.join("control.db");
            let writer = mb_store::ControlStore::open(&path, &keys).unwrap();
            writer.put_record("test", b"id", b"original").unwrap();
            drop(writer);
            let (_reader, guard) =
                crate::volume::open_preserved_control_store(&data, &keys).unwrap();
            let target = temp.path().join("export");
            let mut changed = false;
            let error = export_withdrawn_revision_in_parent(
                &keys,
                &revision,
                &target,
                None,
                |id| {
                    let constructing = fs::read_dir(temp.path()).unwrap().any(|entry| {
                        entry
                            .unwrap()
                            .file_name()
                            .as_encoded_bytes()
                            .starts_with(b".mutualbackup-legacy-export-")
                    });
                    if !changed && (!during_construction || constructing) {
                        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
                        file.write_all(b"changed original input").unwrap();
                        file.sync_all().unwrap();
                        changed = true;
                    }
                    Ok(sectors[id].clone())
                },
                || guard.verify_unchanged(),
            )
            .unwrap_err();
            assert!(changed);
            assert!(
                error.to_string().contains("preserved database changed"),
                "{error:#}"
            );
            assert!(!target.exists());
            assert_eq!(
                fs::read_dir(temp.path()).unwrap().count(),
                1,
                "owned staging remains"
            );
            assert_eq!(fs::read_dir(&data).unwrap().count(), 1);
        }
    }

    #[test]
    fn legacy_export_rejects_parent_replacement_before_staging_and_publication() {
        for during_construction in [false, true] {
            let (keys, revision, sectors) = fixture(7);
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("original");
            let parent = temp.path().join("export-parent");
            let preserved = temp.path().join("preserved-source");
            for path in [&data, &parent, &preserved] {
                fs::create_dir(path).unwrap();
            }
            fs::write(preserved.join("witness"), b"preserved bytes").unwrap();
            let store = mb_store::ControlStore::open(data.join("control.db"), &keys).unwrap();
            let root = crate::control::ProtectedRoot {
                format_version: 4,
                root_id: Uuid::new_v4(),
                path: preserved.clone(),
                filesystem_id: 7,
                root_inode: preserved.metadata().unwrap().ino(),
            };
            store
                .put_record(
                    "protected-root",
                    root.root_id.as_bytes(),
                    &canonical_bytes(&root).unwrap(),
                )
                .unwrap();
            drop(store);
            let files = || -> BTreeMap<_, _> {
                fs::read_dir(&data)
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        (entry.file_name(), fs::read(entry.path()).unwrap())
                    })
                    .collect()
            };
            let before = files();
            let pinned = remote::export_parent_preflight(&keys, &data, &parent, &[]).unwrap();
            let moved = temp.path().join("original-export-parent");
            let target = parent.join("export");
            let mut replaced = false;
            let error = export_withdrawn_revision_in_parent(
                &keys,
                &revision,
                &target,
                Some(pinned),
                |id| {
                    if !replaced
                        && (!during_construction
                            || fs::read_dir(&parent).unwrap().any(|entry| {
                                entry
                                    .unwrap()
                                    .file_name()
                                    .as_encoded_bytes()
                                    .starts_with(b".mutualbackup-legacy-export-")
                            }))
                    {
                        fs::rename(&parent, &moved).unwrap();
                        std::os::unix::fs::symlink(&preserved, &parent).unwrap();
                        replaced = true;
                    }
                    Ok(sectors[id].clone())
                },
                || Ok(()),
            )
            .unwrap_err();
            assert!(replaced);
            assert!(
                error
                    .to_string()
                    .contains("export destination parent changed during recovery"),
                "{error:#}"
            );
            assert_eq!(
                fs::read_dir(&moved).unwrap().count(),
                0,
                "staging remained in the original checked directory"
            );
            assert!(!preserved.join("export").exists());
            assert_eq!(
                fs::read(preserved.join("witness")).unwrap(),
                b"preserved bytes"
            );
            assert_eq!(fs::read_dir(&preserved).unwrap().count(), 1);
            assert!(files() == before, "preserved catalog files changed");
        }
    }

    #[test]
    fn legacy_export_catalog_invalid_or_unavailable_inputs_never_publish() {
        for mode in 0..5 {
            let (keys, mut revision, sectors) = fixture(6);
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("original");
            fs::create_dir(&data).unwrap();
            let mut store = mb_store::ControlStore::open(data.join("control.db"), &keys).unwrap();
            if mode == 1 {
                revision.signature[0] ^= 1;
            }
            if mode != 0 {
                store
                    .put_record(
                        "user-revision",
                        revision.value.revision_id.as_bytes(),
                        &canonical_bytes(&revision).unwrap(),
                    )
                    .unwrap();
            }
            if mode != 2 {
                for (index, reference) in revision
                    .value
                    .metadata_sectors
                    .iter()
                    .chain(&revision.value.data_sectors)
                    .enumerate()
                {
                    store
                        .stage_recovery_shard(
                            &[61; 32],
                            &if mode == 3 {
                                [62; 32]
                            } else {
                                revision.value.guild_id
                            },
                            &[index as u8; 32],
                            0,
                            &reference.root,
                            &sectors[&reference.id],
                        )
                        .unwrap();
                }
            }
            if mode == 4 {
                store
                    .put_record(
                        "user-revision",
                        revision.value.revision_id.as_bytes(),
                        b"malformed",
                    )
                    .unwrap();
            }
            drop(store);
            let original = fs::read(data.join("control.db")).unwrap();
            let target = temp.path().join("export");
            assert!(
                export_withdrawn_revision_from_catalog(
                    &keys,
                    &data,
                    revision.value.revision_id,
                    &target
                )
                .is_err()
            );
            assert!(!target.exists());
            assert_eq!(fs::read(data.join("control.db")).unwrap(), original);
            assert!(!data.join("control.key").exists());
        }
    }

    #[test]
    fn legacy_export_preserves_raw_sparse_hardlinks_metadata_and_stock_git_history() {
        for format in [6, 7] {
            let (keys, revision, sectors) = fixture(format);
            let temp = tempfile::tempdir().unwrap();
            let target = temp.path().join("export");
            let report = export_withdrawn_revision_from_source(&keys, &revision, &target, |id| {
                Ok(sectors[id].clone())
            })
            .unwrap();
            assert_eq!(report.private_format, format);
            assert_eq!(report.namespace_entries, 3);
            assert_eq!(
                fs::read(target.join("signed-revision.postcard")).unwrap(),
                canonical_bytes(&revision).unwrap()
            );
            assert_eq!(
                serde_json::from_slice::<LegacyExportReport>(
                    &fs::read(target.join("export.json")).unwrap()
                )
                .unwrap(),
                report
            );
            let tree = target.join("namespace");
            let first = tree.join(std::ffi::OsString::from_vec(b"nested/\xfe".to_vec()));
            let second = tree.join(std::ffi::OsString::from_vec(b"nested/\xff".to_vec()));
            let a = fs::metadata(&first).unwrap();
            let b = fs::metadata(&second).unwrap();
            assert_eq!(a.ino(), b.ino());
            assert_eq!(a.nlink(), 2);
            assert_eq!(a.mode() & 0o7777, 0o640);
            assert_eq!(a.uid(), unsafe { libc::geteuid() });
            assert_eq!(a.gid(), unsafe { libc::getegid() });
            assert_eq!((a.atime(), a.atime_nsec()), (1_700_000_000, 123));
            assert_eq!((a.mtime(), a.mtime_nsec()), (1_700_000_001, 456));
            assert!(a.blocks() * 512 < a.len());
            let content = fs::read(&first).unwrap();
            assert_eq!(&content[1000..1003], b"raw");
            assert!(
                content[..1000]
                    .iter()
                    .chain(&content[1003..])
                    .all(|byte| *byte == 0)
            );
            let stat = fs::metadata(&tree).unwrap();
            assert_eq!(stat.mode() & 0o7777, 0o750);
            assert_eq!((stat.mtime(), stat.mtime_nsec()), (1_700_000_001, 456));
            if format == 7 {
                let descriptor = git_descriptor(
                    revision.value.protected_root_id,
                    revision.value.data_sectors[0].clone(),
                );
                let repository = git2::Repository::open_bare(target.join("history.git")).unwrap();
                assert_eq!(
                    repository
                        .find_reference("HEAD")
                        .unwrap()
                        .symbolic_target()
                        .unwrap(),
                    Some("refs/heads/topic")
                );
                assert_eq!(
                    repository.references().unwrap().count(),
                    descriptor.refs.len()
                );
                for reference in descriptor.refs {
                    assert_eq!(
                        repository
                            .find_reference(std::str::from_utf8(&reference.name).unwrap())
                            .unwrap()
                            .target()
                            .unwrap()
                            .as_bytes(),
                        reference.oid
                    );
                }
                for object in descriptor.objects {
                    assert_eq!(
                        repository
                            .odb()
                            .unwrap()
                            .read(git2::Oid::from_bytes(&object.oid).unwrap())
                            .unwrap()
                            .data(),
                        object.bytes
                    );
                }
                assert_eq!(
                    repository
                        .find_blob(git2::Oid::from_bytes(&descriptor.blobs[0].oid).unwrap())
                        .unwrap()
                        .content(),
                    b"raw"
                );
                assert!(
                    std::process::Command::new("git")
                        .arg("--git-dir")
                        .arg(target.join("history.git"))
                        .args(["fsck", "--strict"])
                        .status()
                        .unwrap()
                        .success()
                );
                assert_eq!(report.git_objects, Some(4));
            } else {
                assert!(!target.join("history.git").exists());
            }
            assert!(
                export_withdrawn_revision_from_source(&keys, &revision, &target, |id| Ok(sectors
                    [id]
                    .clone()))
                .is_err()
            );
        }
    }

    #[test]
    fn legacy_export_missing_corrupt_unauthorized_and_changing_inputs_never_publish() {
        let (keys, revision, sectors) = fixture(7);
        for case in 0..6 {
            let temp = tempfile::tempdir().unwrap();
            let target = temp.path().join("export");
            let mut changed = revision.clone();
            let mut reads = 0;
            if case == 0 {
                changed.signature[0] ^= 1;
            }
            let result = export_withdrawn_revision_from_source(&keys, &changed, &target, |id| {
                reads += 1;
                if case == 1 {
                    bail!("missing metadata/ciphertext");
                }
                let mut bytes = sectors[id].clone();
                if case == 2 {
                    bytes[0] ^= 1;
                }
                if case == 3 {
                    bytes.pop();
                }
                // The second data read occurs during output construction,
                // after the complete signed-root availability preflight.
                if case == 4 && reads > sectors.len() + 1 {
                    bytes[0] ^= 1;
                }
                Ok(bytes)
            });
            if case == 5 {
                assert!(result.is_ok());
                continue;
            }
            assert!(result.is_err());
            assert!(!target.exists());
            assert!(fs::read_dir(temp.path()).unwrap().next().is_none());
        }
        let wrong_keys = KeyMaterial::from_seed(&Seed::from_bytes([99; 32]));
        let temp = tempfile::tempdir().unwrap();
        let mut oversized = revision.clone();
        oversized.value.writer_signature = vec![0; V1_MAX_CATALOG_BYTES];
        let error = export_withdrawn_revision_from_source(
            &keys,
            &oversized,
            &temp.path().join("oversized"),
            |_| -> Result<Vec<u8>> { panic!("size rejection must precede fetch") },
        )
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<mb_core::ModelError>(),
            Some(mb_core::ModelError::EncodingTooLarge { .. })
        ));
        assert!(
            export_withdrawn_revision_from_source(
                &wrong_keys,
                &revision,
                &temp.path().join("export"),
                |_| -> Result<Vec<u8>> { panic!("must reject before fetch") }
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_export_git_stream_rejects_wrong_lengths_objects_and_nonempty_refs() {
        let (_, revision, _) = fixture(7);
        let descriptor = git_descriptor(
            revision.value.protected_root_id,
            revision.value.data_sectors[0].clone(),
        );
        for case in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let repository = git2::Repository::init_bare(temp.path()).unwrap();
            let existing = if case == 4 {
                let id = repository.blob(b"existing").unwrap();
                repository
                    .reference("refs/mutualbackup/pins/existing", id, false, "existing")
                    .unwrap();
                Some(id)
            } else {
                None
            };
            let mut calls = 0;
            let result = descriptor.export_to_bare(temp.path(), |_, output| {
                calls += 1;
                match case {
                    0 => output.write_all(b"xx"),
                    1 => output.write_all(b"toolong"),
                    2 => output.write_all(b"bad"),
                    _ => Err(std::io::Error::other("blob input unavailable")),
                }
            });
            assert!(result.is_err());
            assert_eq!(calls, if case == 4 { 0 } else { 1 });
            assert!(!temp.path().join("HEAD.lock").exists());
            assert_eq!(
                repository.references().unwrap().count(),
                usize::from(case == 4)
            );
            if let Some(existing) = existing {
                assert_eq!(
                    repository
                        .find_reference("refs/mutualbackup/pins/existing")
                        .unwrap()
                        .target(),
                    Some(existing)
                );
            }
        }
    }

    #[test]
    fn legacy_export_file_inputs_are_bounded_read_only_and_no_follow() {
        let (keys, revision, sectors) = fixture(6);
        let temp = tempfile::tempdir().unwrap();
        let inputs = temp.path().join("inputs");
        fs::create_dir(&inputs).unwrap();
        let sector_path = inputs.join("sectors");
        fs::create_dir(&sector_path).unwrap();
        let input = inputs.join("revision.postcard");
        let signed = canonical_bytes(&revision).unwrap();
        fs::write(&input, &signed).unwrap();
        for (id, bytes) in &sectors {
            fs::write(sector_path.join(format!("{}.bin", hex::encode(id))), bytes).unwrap();
        }
        let target = temp.path().join("export");
        export_withdrawn_revision_from_files(&keys, &input, &sector_path, &target).unwrap();
        assert_eq!(fs::read(&input).unwrap(), signed);
        for (id, bytes) in &sectors {
            assert_eq!(
                fs::read(sector_path.join(format!("{}.bin", hex::encode(id)))).unwrap(),
                *bytes
            );
        }
        assert!(
            export_withdrawn_revision_from_files(
                &keys,
                &input,
                &sector_path,
                &inputs.join("export")
            )
            .is_err()
        );
        let link = temp.path().join("revision-link");
        std::os::unix::fs::symlink(&input, &link).unwrap();
        assert!(
            export_withdrawn_revision_from_files(
                &keys,
                &link,
                &sector_path,
                &temp.path().join("rejected")
            )
            .is_err()
        );
        let metadata = revision.value.metadata_sectors[0].id;
        let ciphertext = sector_path.join(format!("{}.bin", hex::encode(metadata)));
        fs::remove_file(&ciphertext).unwrap();
        std::os::unix::fs::symlink(&input, &ciphertext).unwrap();
        assert!(
            export_withdrawn_revision_from_files(
                &keys,
                &input,
                &sector_path,
                &temp.path().join("rejected")
            )
            .is_err()
        );
        assert!(!temp.path().join("rejected").exists());
    }
}
