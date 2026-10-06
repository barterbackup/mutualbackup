//! Offline, mount-free export of authenticated withdrawn private formats.
//! Original catalogs and explicitly selected preserved anchors are read-only.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
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

/// Export one owner/writer-signed legacy revision into a new package. Required
/// ciphertexts must be available and match every signed reference/commitment.
/// The package contains `namespace`, optional `history.git`, signed provenance
/// and a report. It is independent of native enrollment and is not permission
/// to retire the original installation, retained revisions or peer data.
pub fn export_withdrawn_revision_from_source<F>(
    keys: &KeyMaterial,
    revision: &SignedRecord<UserRevision>,
    target: &Path,
    mut load: F,
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
    let parent = PinnedDirectory::open(parent_path)?;
    ensure!(
        parent.entry_identity(name, true)?.is_none(),
        "export target already exists"
    );
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
    export_withdrawn_revision_from_source(keys, &revision, target, |id| {
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
    })
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
    let control = crate::volume::inspect_control_store(&data_dir, keys)?
        .context("original control catalog is unavailable")?;
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
    export_withdrawn_revision_from_source(keys, &revision, target, |id| {
        let reference = references
            .get(id)
            .context("unsigned legacy sector requested")?;
        let local_error = match load_local(reference) {
            Ok(Some(bytes)) => return Ok(bytes),
            Ok(None) => None,
            Err(error) => Some(error),
        };
        let Some(locator) = recovered.get(&reference.root) else {
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
    })
}

#[cfg(test)]
mod tests {
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
            let (keys, revision, sectors) = fixture(if mode == 3 { 7 } else { 6 });
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("original");
            fs::create_dir(&data).unwrap();
            let mut store = if mode == 0 {
                mb_store::ControlStore::open(data.join("control.db"), &keys).unwrap()
            } else {
                crate::volume::open_control_store(&data, &keys).unwrap().0
            };
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
                    "UPDATE meta SET value = X'00000008' WHERE key = 'schema_version'",
                    false,
                )
                .unwrap();
            drop(store);
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
            let inspected = crate::volume::inspect_control_store(&data, &keys)
                .unwrap()
                .unwrap();
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
                        &inspected,
                        &keys,
                        revision.value.guild_id,
                        reference
                    )
                    .unwrap()
                    .is_some()
                        || mode >= 2
                );
            }
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
